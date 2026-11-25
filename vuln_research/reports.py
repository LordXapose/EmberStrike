import json
from dataclasses import asdict

from .models import Advisory, ResearchReport


NEXT_STEPS = [
    "Confirm the product, exact build, and patch level using an approved inventory or vendor-supported method.",
    "Review the linked vendor advisory and compare its affected-version guidance with the observed asset.",
    "Use only non-invasive, vendor-documented checks; do not probe or exploit the asset as part of this report.",
    "Record the evidence and any uncertainty, and remain within written authorization and scope.",
]


def to_json(report: ResearchReport) -> str:
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=False)


def to_markdown(report: ResearchReport) -> str:
    asset = report.asset
    lines = [
        "# EmberStrike — Vulnerability research report",
        "",
        "> Research aid only. All findings are possible matches, not confirmation that an asset is vulnerable.",
        "> Use only within written authorization and scope. This tool does not contact the assessed asset.",
        "",
        "## ASSET",
        f"- **Assessment:** {asset.assessment}",
        f"- **Scope notes:** {asset.scope_notes or 'Not provided'}",
        f"- **Asset:** {asset.asset or 'Not provided'}",
        f"- **Service:** {' '.join(part for part in (asset.service, asset.product) if part) or 'Not provided'}",
        f"- **Vendor / version / build:** {' / '.join(part or 'Not provided' for part in (asset.vendor, asset.version, asset.build))}",
        f"- **Port / protocol:** {str(asset.port) if asset.port is not None else 'Not provided'} / {asset.protocol or 'Not provided'}",
        f"- **Platform:** {asset.platform or 'Not provided'}",
        f"- **Modules / configuration:** {asset.modules or 'Not provided'}",
        f"- **Identified by / confidence:** {asset.identified_by or 'Not provided'} / {asset.confidence}",
        "",
        "## POSSIBLE MATCHES",
    ]
    if report.offline:
        lines += ["", "Offline mode was selected; no public sources were queried."]
    elif not report.matches:
        lines += ["", "No possible matches were found in the available source results. This does not establish that the asset is unaffected."]
    for match in report.matches:
        advisory = match.advisory
        lines += [
            "",
            f"### {advisory.cve_id} — {advisory.title}",
            f"- **Severity:** {advisory.severity}",
            f"- **Published / updated:** {advisory.published or 'Unavailable'} / {advisory.updated or 'Unavailable'}",
            f"- **Match confidence:** {match.confidence}",
            f"- **Known exploitation:** {'Yes — ' + advisory.exploitation_note if advisory.known_exploited else 'Not reported by the queried trusted sources'}",
            f"- **Affected product/version:** {'; '.join(item.label() for item in advisory.affected) or 'Unavailable'}",
            f"- **Why it may match:** {' '.join(match.why_match) or 'Insufficient product-specific evidence.'}",
            f"- **Missing evidence:** {' '.join(match.missing_evidence) or 'No additional evidence gaps identified; this is still not host-level verification.'}",
            f"- **Conflicting evidence:** {' '.join(match.conflicting_evidence) or 'None identified from the supplied details.'}",
            f"- **Remediation guidance:** {advisory.remediation or 'Review the vendor advisory and follow its supported upgrade or mitigation guidance.'}",
            f"- **Vendor advisory links:** {', '.join(advisory.vendor_advisories) or 'No vendor advisory link was identified.'}",
            f"- **Primary source links:** {', '.join(advisory.references) or 'Unavailable'}",
            "- **Safe verification:** Confirm the installed package/build through an authorized inventory or vendor-supported read-only method, then compare with the linked advisory. Do not send test payloads.",
        ]
    lines += ["", "## EVIDENCE", ""]
    if report.source_warnings:
        lines.extend(f"- Source limitation: {warning}" for warning in report.source_warnings)
    elif report.offline:
        lines.append("- No sources were queried (offline mode).")
    else:
        lines.append("- Public-source records and the supplied observation were compared. No request was sent to the assessed asset.")
    lines += ["", "## NEXT STEPS"]
    lines.extend(f"{number}. {step}" for number, step in enumerate(NEXT_STEPS, 1))
    return "\n".join(lines)


def to_plain(report: ResearchReport) -> str:
    # Plain output is a compact, ANSI-free rendering suitable for logs and redirected output.
    lines = [
        "EMBERSTRIKE — VULNERABILITY RESEARCH REPORT",
        "Research aid only: all findings are possible matches, not proof of vulnerability.",
        "No request is sent to the assessed asset. Stay within written authorization and scope.",
        "",
        "ASSET",
        f"Assessment: {report.asset.assessment}",
        f"Scope: {report.asset.scope_notes or 'Not provided'}",
        f"Asset: {report.asset.asset or 'Not provided'}",
        f"Service/product: {' '.join(part for part in (report.asset.service, report.asset.product) if part) or 'Not provided'}",
        f"Vendor/version/build: {' / '.join(part or 'Not provided' for part in (report.asset.vendor, report.asset.version, report.asset.build))}",
        f"Port/protocol: {report.asset.port or 'Not provided'} / {report.asset.protocol or 'Not provided'}",
        "",
        "POSSIBLE MATCHES",
    ]
    if report.offline:
        lines.append("Offline mode: no public sources were queried.")
    if not report.matches and not report.offline:
        lines.append("No possible matches found in available results; this does not establish that the asset is unaffected.")
    for match in report.matches:
        advisory = match.advisory
        lines += [
            f"{advisory.cve_id} | {advisory.title}",
            f"  Severity: {advisory.severity} | Confidence: {match.confidence} | Published: {advisory.published or 'Unavailable'}",
            f"  Affected: {'; '.join(item.label() for item in advisory.affected) or 'Unavailable'}",
            f"  Why: {' '.join(match.why_match)}",
            f"  Missing evidence: {' '.join(match.missing_evidence) or 'None identified'}",
            f"  Conflicts: {' '.join(match.conflicting_evidence) or 'None identified'}",
            f"  Exploitation status: {'Known exploited — CISA KEV' if advisory.known_exploited else 'Not reported'}",
            f"  Remediation: {advisory.remediation or 'Review linked vendor guidance.'}",
            f"  Sources: {', '.join(advisory.vendor_advisories + advisory.references) or 'Unavailable'}",
            "  Safe verification: Check installed build with an approved inventory/vendor-supported method; do not send test payloads.",
        ]
    lines += ["", "EVIDENCE"]
    lines.extend(f"- {warning}" for warning in report.source_warnings)
    if not report.source_warnings and not report.offline:
        lines.append("- Public-source records compared with supplied details; the asset was not contacted.")
    lines += ["", "NEXT STEPS"]
    lines.extend(f"{number}. {step}" for number, step in enumerate(NEXT_STEPS, 1))
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
    affected = "; ".join(item.label() for item in advisory.affected) or "Unavailable"
    lines = [
        f"# {advisory.cve_id} — {advisory.title}",
        "",
        "> Public advisory information only. This does not verify that a particular host is vulnerable.",
        "",
        "## ADVISORY DETAILS",
        f"- **Severity:** {advisory.severity}",
        f"- **Published / updated:** {advisory.published or 'Unavailable'} / {advisory.updated or 'Unavailable'}",
        f"- **Affected products / versions:** {affected}",
        f"- **Known exploited:** {'Yes — listed in CISA KEV. ' + advisory.exploitation_note if advisory.known_exploited else 'Not reported by the queried sources'}",
        f"- **Remediation:** {advisory.remediation or 'Review the vendor security advisory for supported remediation.'}",
        "",
        "## DESCRIPTION",
        advisory.description or "No description was returned by the queried sources.",
        "",
        "## PRIMARY SOURCES AND VENDOR GUIDANCE",
    ]
    links = list(dict.fromkeys(advisory.vendor_advisories + advisory.references))
    lines.extend(f"- {link}" for link in links)
    if not links:
        lines.append("- No source links were returned.")
    lines += [
        "",
        "## SAFE VERIFICATION",
        "Confirm the installed build using an authorized inventory or vendor-supported, non-invasive method. Do not treat this public advisory as host-level confirmation.",
    ]
    if source_warnings:
        lines += ["", "## SOURCE NOTICES"]
        lines.extend(f"- {warning}" for warning in source_warnings)
    return "\n".join(lines)


def advisory_to_plain(advisory: Advisory, source_warnings: list[str] | None = None) -> str:
    affected = "; ".join(item.label() for item in advisory.affected) or "Unavailable"
    links = list(dict.fromkeys(advisory.vendor_advisories + advisory.references))
    lines = [
        f"{advisory.cve_id} — {advisory.title}",
        "Public advisory details only; this does not verify a specific host.",
        "",
        "ADVISORY DETAILS",
        f"Severity: {advisory.severity}",
        f"Published / updated: {advisory.published or 'Unavailable'} / {advisory.updated or 'Unavailable'}",
        f"Affected products / versions: {affected}",
        f"Known exploited: {'Yes — CISA KEV' if advisory.known_exploited else 'Not reported by the queried sources'}",
        f"Remediation: {advisory.remediation or 'Review the vendor security advisory for supported remediation.'}",
        "",
        "DESCRIPTION",
        advisory.description or "No description was returned by the queried sources.",
        "",
        "PRIMARY SOURCES AND VENDOR GUIDANCE",
    ]
    lines.extend(links or ["No source links were returned."])
    lines.extend([
        "",
        "SAFE VERIFICATION",
        "Confirm the installed build using an authorized inventory or vendor-supported, non-invasive method.",
    ])
    if source_warnings:
        lines.extend(["", "SOURCE NOTICES", *source_warnings])
    return "\n".join(lines)
