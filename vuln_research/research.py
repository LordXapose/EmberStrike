import re

from .cache import capture_cache_events, format_cache_events
from .matching import rank_matches
from .models import Advisory, AssetObservation, ResearchReport
from .sources import cisa_kev, nvd
from .sources.base import SourceError


def _severity_rank(severity: str) -> int | None:
    normalized = severity.upper()
    for level, rank in (("CRITICAL", 4), ("HIGH", 3), ("MEDIUM", 2), ("LOW", 1)):
        if re.search(rf"\b{level}\b", normalized):
            return rank
    score_match = re.match(r"\s*(\d+(?:\.\d+)?)\s*(?:\(|$)", normalized)
    if not score_match:
        return None
    score = float(score_match.group(1))
    if score >= 9.0:
        return 4
    if score >= 7.0:
        return 3
    if score >= 4.0:
        return 2
    if score > 0:
        return 1
    return None


def filter_report_severity(report: ResearchReport, include_low: bool = False) -> ResearchReport:
    if include_low:
        return report
    visible = []
    hidden = 0
    for match in report.matches:
        rank = _severity_rank(match.advisory.severity)
        if rank is not None and rank >= 2:
            visible.append(match)
        else:
            hidden += 1
    report.matches = visible
    report.hidden_severity_matches += hidden
    return report


def run_research(
    asset: AssetObservation,
    offline: bool = False,
    limit: int | None = None,
    refresh_cache: bool = False,
) -> ResearchReport:
    advisories: list[Advisory] = []
    warnings = []
    query = " ".join(part for part in (asset.vendor, asset.product or asset.service) if part).strip()
    with capture_cache_events() as cache_events:
        if query:
            try:
                advisories.extend(nvd.search(query, offline=offline, refresh=refresh_cache))
            except SourceError as exc:
                warnings.append(f"NVD: {exc}")
        else:
            warnings.append("NVD: No product or service name was supplied, so no search was made.")

        try:
            advisories.extend(cisa_kev.fetch_all(offline=offline, refresh=refresh_cache))
        except SourceError as exc:
            warnings.append(f"CISA KEV: {exc}")

    return ResearchReport(
        asset=asset,
        matches=rank_matches(advisories, asset, limit),
        source_warnings=warnings,
        source_status=format_cache_events(cache_events),
        offline=offline,
    )
