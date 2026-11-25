import json
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


USER_AGENT = "EmberStrike/0.1 (public vulnerability research; no target requests)"


class SourceError(Exception):
    """A public vulnerability source could not be queried or parsed."""


def fetch_json(url: str, timeout: float = 12.0) -> dict:
    request = Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    try:
        with urlopen(request, timeout=timeout) as response:
            return json.loads(response.read())
    except HTTPError as exc:
        if exc.code == 429:
            detail = "rate limited this request"
            retry_after = exc.headers.get("Retry-After")
            if retry_after:
                detail += f" (Retry-After: {retry_after})"
        else:
            detail = f"returned HTTP {exc.code}"
        raise SourceError(f"Source {detail}. Try again later or use --offline.") from exc
    except (URLError, TimeoutError, OSError) as exc:
        raise SourceError("Source is unavailable (network or timeout). Try again later or use --offline.") from exc
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise SourceError("Source returned data that could not be read.") from exc
