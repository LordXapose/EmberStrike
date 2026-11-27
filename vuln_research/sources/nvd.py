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
    # CPE 2.3 permits escaped colons inside fields, so a plain split is unsafe.
    parts = []
    field = []
    index = 0
    while index < len(criteria):
        char = criteria[index]
        if char == "\\" and index + 1 < len(criteria):
            field.append(criteria[index + 1])
            index += 2
            continue
        if char == ":":
            parts.append("".join(field))
            field = []
        else:
            field.append(char)
        index += 1
    parts.append("".join(field))
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


def _selected_cvss(metrics: dict) -> dict:
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries:
            metric = next((item for item in entries if item.get("type") == "Primary"), entries[0])
            return metric.get("cvssData", {})
    return {}


def _severity(metrics: dict) -> str:
    score = _selected_cvss(metrics)
    value = score.get("baseSeverity") or score.get("baseScore")
    if value is not None:
        return f"{value} (CVSS {score.get('version', '')})".strip()
    return "Unavailable"


def _cwe_ids(weaknesses: list[dict]) -> list[str]:
    values = []
    for weakness in weaknesses:
        for description in weakness.get("description", []):
            value = description.get("value", "")
            if isinstance(value, str) and re.fullmatch(r"CWE-\d+", value, re.IGNORECASE):
                values.append(value.upper())
    return list(dict.fromkeys(values))


def _affected_range(entry: dict) -> AffectedRange:
    vendor, product, version = _parse_criteria(entry.get("criteria", ""))
    return AffectedRange(
        vendor=vendor,
        product=product,
        version=version,
        start_including=entry.get("versionStartIncluding", ""),
        start_excluding=entry.get("versionStartExcluding", ""),
        end_including=entry.get("versionEndIncluding", ""),
        end_excluding=entry.get("versionEndExcluding", ""),
    )


def _configuration_expression(node: dict) -> str:
    terms = []
    for entry in node.get("cpeMatch", []):
        affected = _affected_range(entry)
        if not affected.product:
            continue
        qualifier = "affected" if entry.get("vulnerable", True) else "required"
        terms.append(f"{qualifier}: {affected.label()}")
    terms.extend(
        expression for child in node.get("children", [])
        if (expression := _configuration_expression(child))
    )
    if not terms:
        return ""
    operator = str(node.get("operator", "OR")).upper()
    if operator not in ("AND", "OR"):
        operator = "OR"
    expression = f" {operator} ".join(terms)
    return f"NOT ({expression})" if node.get("negate") else f"{operator}: {expression}"


def _configuration_summaries(configurations: list[dict]) -> list[str]:
    summaries = []
    for configuration in configurations:
        for node in configuration.get("nodes", []):
            expression = _configuration_expression(node)
            if expression:
                summaries.append(f"Configuration {len(summaries) + 1}: {expression}")
    return list(dict.fromkeys(summaries))


def _advisory(item: dict) -> Advisory:
    cve = item.get("cve", {})
    descriptions = cve.get("descriptions", [])
    description = next((entry.get("value", "") for entry in descriptions if entry.get("lang") == "en"), "")
    affected = []
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for entry in _iter_cpe_matches(node):
                affected.append(_affected_range(entry))
    references = [f"https://nvd.nist.gov/vuln/detail/{cve.get('id', '')}"] if cve.get("id") else []
    vendor_advisories = [
        ref["url"] for ref in cve.get("references", [])
        if ref.get("url") and any(tag.lower() == "vendor advisory" for tag in ref.get("tags", []))
    ]
    title = description.split(". ", 1)[0].strip() if description else cve.get("id", "Untitled advisory")
    nvd_source = references[0] if references else "NVD"
    metrics = cve.get("metrics", {})
    cvss = _selected_cvss(metrics)
    try:
        cvss_score = float(cvss["baseScore"]) if cvss.get("baseScore") is not None else None
    except (TypeError, ValueError):
        cvss_score = None
    cwes = _cwe_ids(cve.get("weaknesses", []))
    cisa_added = cve.get("cisaExploitAdd", "")
    remediation_due = cve.get("cisaActionDue", "")
    remediation = cve.get("cisaRequiredAction", "")
    fact_sources = {
        key: [nvd_source]
        for key, value in {
            "title": title,
            "description": description,
            "severity": _severity(metrics) if metrics else "",
            "cvss": cvss_score,
            "published": cve.get("published", ""),
            "updated": cve.get("lastModified", ""),
            "affected_ranges": affected,
            "affected_configurations": cve.get("configurations", []),
            "cwes": cwes,
            "cvss": cvss_score is not None or bool(cvss.get("vectorString")),
            "kev_date_added": cisa_added,
            "known_exploited": bool(cisa_added),
            "remediation_due": remediation_due,
            "remediation": remediation,
        }.items()
        if value
    }
    if vendor_advisories:
        fact_sources["vendor_advisories"] = list(dict.fromkeys(vendor_advisories))
        fact_sources.setdefault("remediation", list(dict.fromkeys(vendor_advisories)))
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
        known_exploited=bool(cisa_added),
        remediation=remediation,
        sources=["NVD"],
        cvss_score=cvss_score,
        cvss_version=cvss.get("version", ""),
        cvss_vector=cvss.get("vectorString", ""),
        cwes=cwes,
        affected_configurations=_configuration_summaries(cve.get("configurations", [])),
        kev_date_added=cisa_added,
        remediation_due=remediation_due,
        fact_sources=fact_sources,
    )


def search(
    keyword: str,
    limit: int | None = None,
    *,
    offline: bool = False,
    refresh: bool = False,
) -> list[Advisory]:
    if not keyword.strip():
        return []
    if limit is not None and limit < 1:
        raise SourceError("NVD search limit must be at least 1.")

    page_size = min(limit, 2000) if limit is not None else 2000
    start_index = 0
    advisories = []
    total_results = None
    while total_results is None or start_index < total_results:
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": page_size,
            "startIndex": start_index,
        }
        url = f"{NVD_URL}?{urlencode(params)}"
        options = {}
        if offline:
            options["offline"] = True
        if refresh:
            options["refresh"] = True
        data = fetch_json(url, timeout=30.0, **options)
        try:
            vulnerabilities = data.get("vulnerabilities", [])
            if not isinstance(vulnerabilities, list):
                raise TypeError("vulnerabilities is not a list")
            total_results = int(data.get("totalResults", len(vulnerabilities)))
            response_start = int(data.get("startIndex", start_index))
            advisories.extend(_advisory(item) for item in vulnerabilities)
        except (AttributeError, TypeError, ValueError, KeyError) as exc:
            raise SourceError("NVD returned an unexpected response structure.") from exc

        if limit is not None and len(advisories) >= limit:
            return advisories[:limit]
        if not vulnerabilities:
            break
        next_start = response_start + len(vulnerabilities)
        if next_start <= start_index:
            raise SourceError("NVD pagination did not advance; stopping to avoid repeating results.")
        start_index = next_start

    return advisories


def lookup(cve_id: str, *, offline: bool = False, refresh: bool = False) -> Advisory | None:
    normalized_id = cve_id.upper()
    if not re.fullmatch(r"CVE-\d{4}-\d{4,}", normalized_id):
        raise SourceError("Enter a CVE identifier such as CVE-2025-12345.")
    url = f"{NVD_URL}?{urlencode({'cveId': normalized_id})}"
    options = {}
    if offline:
        options["offline"] = True
    if refresh:
        options["refresh"] = True
    data = fetch_json(url, **options)
    vulnerabilities = data.get("vulnerabilities", [])
    if not vulnerabilities:
        return None
    try:
        return _advisory(vulnerabilities[0])
    except (AttributeError, TypeError, KeyError) as exc:
        raise SourceError("NVD returned an unexpected response structure.") from exc
