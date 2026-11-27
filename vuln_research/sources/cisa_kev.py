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
        return [
            Advisory(
                cve_id=entry["cveID"],
                title=entry.get("vulnerabilityName") or entry["cveID"],
                published=entry.get("dateAdded", ""),
                description=entry.get("shortDescription", ""),
                affected=[AffectedRange(
                    vendor=entry.get("vendorProject", ""),
                    product=entry.get("product", ""),
                )],
                known_exploited=True,
                exploitation_note="Listed in CISA's Known Exploited Vulnerabilities catalog.",
                remediation=entry.get("requiredAction", ""),
                sources=["CISA KEV"],
                references=[f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog"],
            )
            for entry in entries
        ]
    except (KeyError, TypeError) as exc:
        raise SourceError("CISA KEV returned an unexpected response structure.") from exc
