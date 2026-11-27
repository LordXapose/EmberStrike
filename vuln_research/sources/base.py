import json
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from ..cache import (
    DEFAULT_TTL_SECONDS,
    _age_seconds,
    _read_entry,
    _write_entry,
    record_cache_event,
)


USER_AGENT = "EmberStrike/0.1 (public vulnerability research; no target requests)"


class SourceError(Exception):
    """A public vulnerability source could not be queried or parsed."""


def fetch_json(
    url: str,
    timeout: float = 12.0,
    *,
    offline: bool = False,
    refresh: bool = False,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
) -> dict:
    cached = _read_entry(url)
    age = _age_seconds(cached[1]) if cached else None
    fresh = cached is not None and age is not None and age < ttl_seconds
    if offline:
        if cached:
            record_cache_event(url, "offline-hit", age)
            return cached[0]
        record_cache_event(url, "offline-miss")
        raise SourceError("No cached response is available for this query while offline.")
    if cached and fresh and not refresh:
        record_cache_event(url, "hit", age)
        return cached[0]

    request = Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    try:
        with urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read())
            if not isinstance(payload, dict):
                raise SourceError("Source returned an unexpected response structure.")
    except HTTPError as exc:
        if exc.code == 429:
            detail = "rate limited this request"
            retry_after = exc.headers.get("Retry-After")
            if retry_after:
                detail += f" (Retry-After: {retry_after})"
        else:
            detail = f"returned HTTP {exc.code}"
        error = SourceError(f"Source {detail}. Try again later or use --offline.")
        if cached:
            record_cache_event(url, "stale", age, str(error))
            return cached[0]
        raise error from exc
    except (URLError, TimeoutError, OSError) as exc:
        error = SourceError("Source is unavailable (network or timeout). Try again later or use --offline.")
        if cached:
            record_cache_event(url, "stale", age, str(error))
            return cached[0]
        raise error from exc
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        error = SourceError("Source returned data that could not be read.")
        if cached:
            record_cache_event(url, "stale", age, str(error))
            return cached[0]
        raise error from exc

    try:
        _write_entry(url, payload, datetime.now(timezone.utc))
    except OSError as exc:
        record_cache_event(url, "write-error", detail=f"Could not save local cache: {exc}")
        record_cache_event(url, "fetched-uncached")
        return payload
    record_cache_event(url, "refreshed" if cached else "fetched")
    return payload
