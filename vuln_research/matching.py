import re
from packaging.version import InvalidVersion, Version

from .models import Advisory, AssetObservation, PossibleMatch


_PRODUCT_GROUPS = (
    {"apache http server", "http server", "httpd"},
    {"apache tomcat", "tomcat"},
    {"microsoft exchange server", "exchange server", "exchange"},
    {"microsoft iis", "iis", "internet information services"},
    {"microsoft sql server", "sql server"},
    {"postgresql", "postgres"},
)


def _normalize(value: str) -> str:
    return " ".join(re.findall(r"[a-z0-9]+", value.lower()))


def _product_forms(value: str) -> set[str]:
    normalized = _normalize(value)
    if not normalized:
        return set()
    for group in _PRODUCT_GROUPS:
        if normalized in group:
            return group
    return {normalized}


def _strip_vendor_prefix(product: str, vendor: str) -> str:
    product_tokens = product.split()
    vendor_tokens = vendor.split()
    if vendor_tokens and product_tokens[:len(vendor_tokens)] == vendor_tokens:
        return " ".join(product_tokens[len(vendor_tokens):])
    return product


def _same_product(
    observed: str,
    candidate: str,
    observed_vendor: str = "",
    candidate_vendor: str = "",
) -> bool:
    observed_norm, candidate_norm = _normalize(observed), _normalize(candidate)
    observed_norm = _strip_vendor_prefix(
        observed_norm,
        _normalize(observed_vendor) or _normalize(candidate_vendor),
    )
    candidate_norm = _strip_vendor_prefix(candidate_norm, _normalize(candidate_vendor))
    return bool(observed_norm and candidate_norm and _product_forms(observed_norm) & _product_forms(candidate_norm))


def _description_mentions_product(description: str, product: str) -> bool:
    normalized_description = _normalize(description)
    return bool(
        normalized_description
        and any(
            form and f" {form} " in f" {normalized_description} "
            for form in _product_forms(product)
        )
    )


def _version_in_range(version: str, affected) -> bool | None:
    if not version:
        return None
    if affected.version and affected.version not in ("*", "-"):
        try:
            return Version(version) == Version(affected.version)
        except InvalidVersion:
            return _normalize(version) == _normalize(affected.version)
    bounds = (
        affected.start_including, affected.start_excluding,
        affected.end_including, affected.end_excluding,
    )
    if not any(bounds):
        return None
    try:
        observed = Version(version)
        if affected.start_including and observed < Version(affected.start_including):
            return False
        if affected.start_excluding and observed <= Version(affected.start_excluding):
            return False
        if affected.end_including and observed > Version(affected.end_including):
            return False
        if affected.end_excluding and observed >= Version(affected.end_excluding):
            return False
        return True
    except InvalidVersion:
        return None


def _unique_affected(affected):
    unique = []
    seen = set()
    for item in affected:
        key = (
            item.vendor, item.product, item.version,
            item.start_including, item.start_excluding,
            item.end_including, item.end_excluding,
        )
        if key not in seen:
            seen.add(key)
            unique.append(item)
    return unique


def match_advisory(advisory: Advisory, asset: AssetObservation) -> PossibleMatch | None:
    observed_product = asset.product or asset.service
    products = [
        item for item in _unique_affected(advisory.affected)
        if _same_product(
            observed_product,
            item.product,
            asset.vendor,
            item.vendor,
        )
    ]
    description_matches = _description_mentions_product(advisory.description, observed_product)
    if not products and not description_matches:
        return None

    vendor_matches = any(
        not asset.vendor or _normalize(asset.vendor) == _normalize(item.vendor)
        for item in products
    )
    why = []
    if products:
        why.append(f"Observed product '{asset.product or asset.service}' matches an affected-product entry.")
    elif description_matches:
        why.append("The product/service name appears in the advisory description; affected-product metadata did not confirm it.")
    if asset.vendor and vendor_matches:
        why.append(f"Observed vendor '{asset.vendor}' matches the source's product metadata.")
    elif asset.vendor and products:
        why.append(f"Observed vendor '{asset.vendor}' does not clearly match the source's vendor metadata.")
    if advisory.known_exploited:
        why.append("CISA lists this CVE in its Known Exploited Vulnerabilities catalog.")

    version_checks = [_version_in_range(asset.version, item) for item in products]
    in_range = any(result is True for result in version_checks)
    known_outside = bool(asset.version and version_checks and all(result is False for result in version_checks))
    missing = []
    conflict = []
    if not asset.version:
        missing.append("Observed product version was not supplied.")
    elif not products or all(result is None for result in version_checks):
        missing.append("The source does not provide a comparable affected-version range for this product.")
    elif in_range:
        why.append(f"Observed version '{asset.version}' falls within a published affected-version range.")
    elif known_outside:
        conflict.append(f"Observed version '{asset.version}' is outside the affected range recorded by this source.")
    if not asset.build:
        missing.append("Build/patch level is unknown; vendors may backport fixes without changing the displayed version.")
    if not asset.vendor:
        missing.append("Vendor was not supplied, so vendor-specific matching could not be confirmed.")
    if not asset.identified_by:
        missing.append("The method used to identify the service was not recorded.")
    if asset.confidence.lower() in ("low", "medium"):
        missing.append(f"Observation confidence is {asset.confidence}; confirm product and version from an authoritative inventory.")
    if not advisory.vendor_advisories:
        missing.append("No vendor advisory link was identified in the returned record; consult the vendor's security notices.")

    if products and asset.vendor and vendor_matches and in_range:
        confidence = "High"
    elif products and vendor_matches:
        confidence = "Medium"
    else:
        confidence = "Low"
    if known_outside:
        confidence = "Low"
    if asset.confidence.lower() == "medium" and confidence == "High":
        confidence = "Medium"
    elif asset.confidence.lower() == "low":
        confidence = "Low"
    return PossibleMatch(advisory, confidence, why, missing, conflict)


def rank_matches(
    advisories: list[Advisory],
    asset: AssetObservation,
    limit: int | None = None,
) -> list[PossibleMatch]:
    by_id: dict[str, Advisory] = {}
    for advisory in advisories:
        if not advisory.cve_id:
            continue
        advisory.affected = _unique_affected(advisory.affected)
        advisory.sources = list(dict.fromkeys(advisory.sources))
        advisory.references = list(dict.fromkeys(advisory.references))
        advisory.vendor_advisories = list(dict.fromkeys(advisory.vendor_advisories))
        existing = by_id.get(advisory.cve_id)
        if existing is None:
            by_id[advisory.cve_id] = advisory
            continue
        existing.known_exploited |= advisory.known_exploited
        existing.sources = sorted(set(existing.sources + advisory.sources))
        existing.references = list(dict.fromkeys(existing.references + advisory.references))
        existing.vendor_advisories = list(dict.fromkeys(existing.vendor_advisories + advisory.vendor_advisories))
        existing.remediation = existing.remediation or advisory.remediation
        existing.affected = _unique_affected(existing.affected + advisory.affected)
        existing.references = list(dict.fromkeys(existing.references))
        existing.vendor_advisories = list(dict.fromkeys(existing.vendor_advisories))
    matches = [
        result for advisory in by_id.values()
        if (result := match_advisory(advisory, asset)) is not None
    ]
    order = {"High": 0, "Medium": 1, "Low": 2}
    matches.sort(key=lambda result: (
        order[result.confidence],
        not result.advisory.known_exploited,
        result.advisory.cve_id,
    ))
    return matches[:limit] if limit is not None else matches
