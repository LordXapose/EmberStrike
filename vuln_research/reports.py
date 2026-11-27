import json
from dataclasses import asdict

from .models import Advisory, ResearchReport


def _short_name(value: str, width: int = 48) -> str:
    value = " ".join(value.split())
    return value if len(value) <= width else value[:width - 3] + "..."


def _ascii_table(headers: tuple[str, ...], rows: list[tuple[str, ...]]) -> list[str]:
    widths = tuple(
        max(len(headers[index]), *(len(row[index]) for row in rows))
        for index in range(len(headers))
    )
    border = "+-" + "-+-".join("-" * width for width in widths) + "-+"
    output = [border]
    output.append("| " + " | ".join(value.ljust(widths[index]) for index, value in enumerate(headers)) + " |")
    output.append(border)
    output.extend(
        "| " + " | ".join(value.ljust(widths[index]) for index, value in enumerate(row)) + " |"
        for row in rows
    )
    output.append(border)
    return output


def _published_date(value: str) -> str:
    return value[:10] if value else "Unknown"


def to_json(report: ResearchReport) -> str:
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=False)


def to_markdown(report: ResearchReport) -> str:
    lines = [
        "# EmberStrike — Possible Vulnerability Matches",
        "",
        "> Possible matches only; this does not confirm that an asset is vulnerable.",
        "> No request is sent to the asset. Stay within written authorization and scope.",
        "",
    ]
    if report.offline:
        lines += ["Offline mode: no network requests were made; matching cached data may be used.", ""]
    if report.source_status:
        lines += ["Source status:"]
        lines.extend(f"- {status}" for status in report.source_status)
        lines.append("")
    if report.hidden_severity_matches:
        lines += [
            f"{report.hidden_severity_matches} low or unscored result(s) hidden. Re-run with `--include-low` to show them.",
            "",
        ]
    if report.matches:
        lines += [
            "| Vulnerability name | CVE | Published | Severity |",
            "| --- | --- | --- | --- |",
        ]
        for match in report.matches:
            advisory = match.advisory
            title = _short_name(advisory.title).replace("|", "\\|")
            lines.append(
                f"| {title} | {advisory.cve_id} | {_published_date(advisory.published)} | {advisory.severity} |"
            )
    else:
        lines += ["No matching records at the selected severity. This does not establish that the asset is unaffected."]
    if report.source_warnings:
        lines += ["", "Source notices:"]
        lines.extend(f"- {warning}" for warning in report.source_warnings)
    return "\n".join(lines)


def to_plain(report: ResearchReport) -> str:
    lines = [
        "POSSIBLE VULNERABILITIES",
        "Possible matches only; no requests were sent to the assessed asset.",
    ]
    if report.offline:
        lines.append("Offline mode: no network requests were made; matching cached data may be used.")
    lines.extend(f"Source status: {status}" for status in report.source_status)
    if report.hidden_severity_matches:
        lines.append(
            f"{report.hidden_severity_matches} low or unscored result(s) hidden; use --include-low to show all severities."
        )
    if report.matches:
        rows = [
            (
                _short_name(match.advisory.title),
                match.advisory.cve_id,
                _published_date(match.advisory.published),
                match.advisory.severity,
            )
            for match in report.matches
        ]
        lines.extend(_ascii_table(("Vulnerability name", "CVE", "Published", "Severity"), rows))
    elif not report.offline:
        lines.append("No Critical, High, or Medium records found. Use --include-low to view all results.")
    lines.extend(f"- {warning}" for warning in report.source_warnings)
    return "\n".join(lines)


def advisory_to_dict(advisory: Advisory, source_warnings: list[str] | None = None) -> dict:
    return {
        "advisory": asdict(advisory),
        "source_warnings": source_warnings or [],
        "notice": "Public advisory details only; this does not verify a specific host.",
        "safe_verification": "Confirm the installed build using an authorized inventory or vendor-supported, non-invasive method.",
    }


def advisory_to_json(advisory: Advisory, source_warnings: list[str] | None = None) -> str:
    return json.dumps(advisory_to_dict(advisory, source_warnings), indent=2, ensure_ascii=False)


def advisory_to_markdown(advisory: Advisory, source_warnings: list[str] | None = None) -> str:
    affected = [item.label() for item in advisory.affected[:3]]
    if len(advisory.affected) > len(affected):
        affected.append(f"...and {len(advisory.affected) - len(affected)} more; see NVD record")
    remediation = " ".join(advisory.remediation.split()) or "See vendor advisory"
    rows = [
        ("CVE", advisory.cve_id),
        ("Vulnerability name", _short_name(advisory.title, 120)),
        ("Severity", advisory.severity),
        ("Published", _published_date(advisory.published)),
        ("Updated", _published_date(advisory.updated)),
        ("Known exploited", "Yes (CISA KEV)" if advisory.known_exploited else "Not listed"),
        ("Affected ranges", "; ".join(affected) or "See linked advisory"),
        ("Remediation", remediation[:160] + ("..." if len(remediation) > 160 else "")),
    ]
    lines = [
        f"# {advisory.cve_id} — {_short_name(advisory.title, 120)}",
        "",
        "> Public advisory only; this does not verify a specific host.",
        "",
        "| Name | Information |",
        "| --- | --- |",
    ]
    for name, value in rows:
        escaped_value = " ".join(value.split()).replace("|", "\\|")
        lines.append(f"| {name} | {escaped_value} |")
    lines += ["", "## SOURCE LINKS"]
    links = _advisory_links(advisory)
    lines += ["| Name | Link |", "| --- | --- |"]
    lines.extend(f"| {name} | {link} |" for name, link in links)
    if not links:
        lines.append("| Unavailable | No source links |")
    if source_warnings:
        lines += ["", "## SOURCE NOTICES"]
        lines.extend(f"- {warning}" for warning in source_warnings)
    return "\n".join(lines)


def advisory_to_plain(advisory: Advisory, source_warnings: list[str] | None = None) -> str:
    affected = [item.label() for item in advisory.affected[:3]]
    if len(advisory.affected) > len(affected):
        affected.append(f"...and {len(advisory.affected) - len(affected)} more; see NVD record")
    remediation = " ".join(advisory.remediation.split()) or "See vendor advisory"
    rows = [
        ("CVE", advisory.cve_id),
        ("Vulnerability name", _short_name(advisory.title, 120)),
        ("Severity", advisory.severity),
        ("Published", _published_date(advisory.published)),
        ("Updated", _published_date(advisory.updated)),
        ("Known exploited", "Yes (CISA KEV)" if advisory.known_exploited else "Not listed"),
        ("Affected ranges", "; ".join(affected) or "See linked advisory"),
        ("Remediation", remediation[:160] + ("..." if len(remediation) > 160 else "")),
    ]
    lines = [
        f"DETAILS FOR {advisory.cve_id}",
        "Public advisory only; this does not verify a specific host.",
        *_ascii_table(("Name", "Information"), rows),
        "",
        "SOURCE LINKS",
        *_ascii_table(("Name", "Link"), _advisory_links(advisory) or [("Unavailable", "No source links")]),
    ]
    if source_warnings:
        lines.extend(["", "SOURCE NOTICES", *_ascii_table(("Notice",), [(warning,) for warning in source_warnings])])
    return "\n".join(lines)


def _advisory_links(advisory: Advisory) -> list[tuple[str, str]]:
    links = []
    for link in list(dict.fromkeys(advisory.vendor_advisories + advisory.references)):
        if "nvd.nist.gov" in link:
            label = "NVD record"
        elif "cisa.gov" in link:
            label = "CISA KEV"
        elif link in advisory.vendor_advisories:
            label = "Vendor advisory"
        else:
            label = "Source record"
        links.append((label, link))
    return links
