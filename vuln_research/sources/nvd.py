import re
from urllib.parse import urlencode

from ..models import Advisory, AffectedRange
from .base import SourceError, fetch_json


NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _iter_cpe_matches(node: dict):
    for match in node.get("cpeMatch", []):
        if match.get("vulnerable", True):
            yield match
    for child in node.get("children", []):
        yield from _iter_cpe_matches(child)


def _parse_criteria(criteria: str) -> tuple[str, str, str]:
    # CPE 2.3 fields are colon-delimited; vendor/product/version are stable positions.
    parts = criteria.split(":")
    if len(parts) < 6:
        return "", "", ""
    return parts[3].replace("_", " "), parts[4].replace("_", " "), parts[5]


def _unique_affected(entries: list[AffectedRange]) -> list[AffectedRange]:
    unique = []
    seen = set()
    for entry in entries:
        key = (
            entry.vendor, entry.product, entry.version,
            entry.start_including, entry.start_excluding,
            entry.end_including, entry.end_excluding,
        )
        if key not in seen:
            seen.add(key)
            unique.append(entry)
    return unique


def _severity(metrics: dict) -> str:
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries:
            score = entries[0].get("cvssData", {})
            value = score.get("baseSeverity") or score.get("baseScore")
            if value is not None:
                return f"{value} (CVSS {score.get('version', '')})".strip()
    return "Unavailable"


def _advisory(item: dict) -> Advisory:
    cve = item.get("cve", {})
    descriptions = cve.get("descriptions", [])
    description = next((entry.get("value", "") for entry in descriptions if entry.get("lang") == "en"), "")
    affected = []
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for entry in _iter_cpe_matches(node):
                vendor, product, version = _parse_criteria(entry.get("criteria", ""))
                affected.append(AffectedRange(
                    vendor=vendor,
                    product=product,
                    version=version,
                    start_including=entry.get("versionStartIncluding", ""),
                    start_excluding=entry.get("versionStartExcluding", ""),
                    end_including=entry.get("versionEndIncluding", ""),
                    end_excluding=entry.get("versionEndExcluding", ""),
                ))
    references = [f"https://nvd.nist.gov/vuln/detail/{cve.get('id', '')}"] if cve.get("id") else []
    vendor_advisories = [
        ref["url"] for ref in cve.get("references", [])
        if ref.get("url") and any(tag.lower() == "vendor advisory" for tag in ref.get("tags", []))
    ]
    title = description.split(". ", 1)[0].strip() if description else cve.get("id", "Untitled advisory")
    return Advisory(
        cve_id=cve.get("id", ""),
        title=title,
        severity=_severity(cve.get("metrics", {})),
        published=cve.get("published", ""),
        updated=cve.get("lastModified", ""),
        description=description,
        affected=_unique_affected(affected),
        references=list(dict.fromkeys(references)),
        vendor_advisories=list(dict.fromkeys(vendor_advisories)),
        sources=["NVD"],
    )


def search(keyword: str, limit: int = 2000) -> list[Advisory]:
    if not keyword.strip():
        return []
    url = f"{NVD_URL}?{urlencode({'keywordSearch': keyword, 'resultsPerPage': min(limit, 2000)})}"
    data = fetch_json(url, timeout=30.0)
    try:
        return [_advisory(item) for item in data.get("vulnerabilities", [])]
    except (AttributeError, TypeError, KeyError) as exc:
        raise SourceError("NVD returned an unexpected response structure.") from exc


def lookup(cve_id: str) -> Advisory | None:
    normalized_id = cve_id.upper()
    if not re.fullmatch(r"CVE-\d{4}-\d{4,}", normalized_id):
        raise SourceError("Enter a CVE identifier such as CVE-2025-12345.")
    url = f"{NVD_URL}?{urlencode({'cveId': normalized_id})}"
    data = fetch_json(url)
    vulnerabilities = data.get("vulnerabilities", [])
    if not vulnerabilities:
        return None
    try:
        return _advisory(vulnerabilities[0])
    except (AttributeError, TypeError, KeyError) as exc:
        raise SourceError("NVD returned an unexpected response structure.") from exc
