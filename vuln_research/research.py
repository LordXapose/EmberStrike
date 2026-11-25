from .matching import rank_matches
from .models import Advisory, AssetObservation, ResearchReport
from .sources import cisa_kev, nvd
from .sources.base import SourceError


def run_research(asset: AssetObservation, offline: bool = False, limit: int | None = None) -> ResearchReport:
    if offline:
        return ResearchReport(asset=asset, matches=[], offline=True)

    advisories: list[Advisory] = []
    warnings = []
    query = " ".join(part for part in (asset.vendor, asset.product or asset.service) if part).strip()
    if query:
        try:
            advisories.extend(nvd.search(query))
        except SourceError as exc:
            warnings.append(f"NVD: {exc}")
    else:
        warnings.append("NVD: No product or service name was supplied, so no search was made.")

    try:
        advisories.extend(cisa_kev.fetch_all())
    except SourceError as exc:
        warnings.append(f"CISA KEV: {exc}")

    return ResearchReport(asset, rank_matches(advisories, asset, limit), warnings)
