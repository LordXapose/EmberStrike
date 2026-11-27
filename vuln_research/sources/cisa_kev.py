import re

from ..models import Advisory, AffectedRange
from .base import SourceError, fetch_json


KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fetch_all(*, offline: bool = False, refresh: bool = False) -> list[Advisory]:
    options = {}
    if offline:
        options["offline"] = True
    if refresh:
        options["refresh"] = True
    data = fetch_json(KEV_URL, **options)
    try:
        entries = data["vulnerabilities"]
        advisories = []
        for entry in entries:
            cve_id = entry["cveID"]
            cwes = entry.get("cwes", [])
            if isinstance(cwes, str):
                cwes = [cwes]
            if not isinstance(cwes, list):
                cwes = []
            cwes = list(dict.fromkeys(
                value.upper() for value in cwes
                if isinstance(value, str) and re.fullmatch(r"CWE-\d+", value, re.IGNORECASE)
            ))
            reference = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
            title = entry.get("vulnerabilityName") or cve_id
            date_added = entry.get("dateAdded", "")
            remediation = entry.get("requiredAction", "")
            remediation_due = entry.get("dueDate", "")
            affected = [AffectedRange(
                vendor=entry.get("vendorProject", ""),
                product=entry.get("product", ""),
            )]
            fact_sources = {
                key: [reference]
                for key, value in {
                    "title": title,
                    "known_exploited": True,
                    "kev_date_added": date_added,
                    "affected_ranges": affected,
                    "cwes": cwes,
                    "remediation": remediation,
                    "remediation_due": remediation_due,
                }.items()
                if value
            }
            advisories.append(Advisory(
                cve_id=cve_id,
                title=title,
                published=date_added,
                description=entry.get("shortDescription", ""),
                affected=affected,
                known_exploited=True,
                exploitation_note="Listed in CISA's Known Exploited Vulnerabilities catalog.",
                remediation=remediation,
                sources=["CISA KEV"],
                cwes=cwes,
                kev_date_added=date_added,
                remediation_due=remediation_due,
                fact_sources=fact_sources,
                references=[reference],
            ))
        return advisories
    except (KeyError, TypeError) as exc:
        raise SourceError("CISA KEV returned an unexpected response structure.") from exc
