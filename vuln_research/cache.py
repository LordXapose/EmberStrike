import contextvars
import hashlib
import json
import os
import re
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator


DEFAULT_TTL_SECONDS = 24 * 60 * 60
_events: contextvars.ContextVar[list["CacheEvent"] | None] = contextvars.ContextVar(
    "emberstrike_cache_events",
    default=None,
)


@dataclass(frozen=True)
class CacheEvent:
    source: str
    status: str
    age_seconds: int | None = None
    detail: str = ""


@contextmanager
def capture_cache_events() -> Iterator[list[CacheEvent]]:
    events: list[CacheEvent] = []
    token = _events.set(events)
    try:
        yield events
    finally:
        _events.reset(token)


def _source_name(url: str) -> str:
    if "nvd.nist.gov" in url:
        return "NVD"
    if "cisa.gov" in url:
        return "CISA KEV"
    return "Public source"


def record_cache_event(
    url: str,
    status: str,
    age_seconds: int | None = None,
    detail: str = "",
) -> None:
    events = _events.get()
    if events is not None:
        events.append(CacheEvent(_source_name(url), status, age_seconds, detail))


def cache_directory() -> Path:
    override = os.environ.get("EMBERSTRIKE_CACHE_DIR")
    if override:
        return Path(override).expanduser()
    root = os.environ.get("XDG_CACHE_HOME")
    return (Path(root).expanduser() if root else Path.home() / ".cache") / "emberstrike"


def _cache_path(url: str) -> Path:
    key = hashlib.sha256(url.encode("utf-8")).hexdigest()
    return cache_directory() / f"{key}.json"


def _parse_timestamp(value: str) -> datetime | None:
    try:
        timestamp = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    return timestamp.astimezone(timezone.utc)


def _read_entry(url: str) -> tuple[dict, datetime] | None:
    try:
        entry = json.loads(_cache_path(url).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        record_cache_event(url, "read-error", detail=str(exc))
        return None
    if not isinstance(entry, dict) or not isinstance(entry.get("payload"), dict):
        record_cache_event(url, "read-error", detail="Invalid local cache entry.")
        return None
    timestamp = _parse_timestamp(entry.get("cached_at", ""))
    if timestamp is None:
        record_cache_event(url, "read-error", detail="Cache timestamp is invalid.")
        return None
    return entry["payload"], timestamp


def _write_entry(url: str, payload: dict, cached_at: datetime) -> None:
    directory = cache_directory()
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    encoded = json.dumps({
        "source": _source_name(url),
        "cached_at": cached_at.isoformat(),
        "payload": payload,
    }, ensure_ascii=False)
    file_descriptor, temporary_name = tempfile.mkstemp(
        prefix=".emberstrike-cache-",
        suffix=".tmp",
        dir=directory,
    )
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(file_descriptor, 0o600)
        with os.fdopen(file_descriptor, "w", encoding="utf-8") as output:
            output.write(encoded)
        os.replace(temporary_name, _cache_path(url))
    finally:
        if os.path.exists(temporary_name):
            os.unlink(temporary_name)


def _age_seconds(timestamp: datetime) -> int:
    return max(0, int((datetime.now(timezone.utc) - timestamp).total_seconds()))


def format_age(seconds: int) -> str:
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m"
    if seconds < 86400:
        return f"{seconds // 3600}h"
    return f"{seconds // 86400}d"


def format_cache_events(events: list[CacheEvent]) -> list[str]:
    grouped: dict[str, list[CacheEvent]] = {}
    for event in events:
        grouped.setdefault(event.source, []).append(event)

    messages = []
    for source, entries in grouped.items():
        counts: dict[str, int] = {}
        for event in entries:
            counts[event.status] = counts.get(event.status, 0) + 1
        parts = []
        for status, label in (
            ("hit", "cached"),
            ("offline-hit", "cached offline"),
            ("fetched", "fetched and cached"),
            ("fetched-uncached", "fetched but not cached"),
            ("refreshed", "refreshed cache"),
            ("stale", "used stale cache"),
            ("offline-miss", "no cache available offline"),
            ("read-error", "cache read issue"),
            ("write-error", "cache write issue"),
        ):
            count = counts.get(status, 0)
            if count:
                parts.append(f"{count} {label}")
        ages = [
            event.age_seconds for event in entries
            if event.status in ("hit", "offline-hit", "stale") and event.age_seconds is not None
        ]
        if ages:
            parts.append(f"oldest age {format_age(max(ages))}")
        details = list(dict.fromkeys(event.detail for event in entries if event.detail))
        if details:
            parts.append("; ".join(details))
        if parts:
            messages.append(f"{source}: " + ", ".join(parts) + ".")
    return messages


def list_cache_entries() -> list[dict[str, str | int]]:
    directory = cache_directory()
    if not directory.is_dir():
        return []
    entries = []
    for path in directory.glob("*.json"):
        if not re.fullmatch(r"[a-f0-9]{64}\.json", path.name):
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            entries.append({"source": "Unknown", "cached_at": "Unreadable", "age_seconds": -1})
            continue
        if not isinstance(data, dict):
            continue
        timestamp = _parse_timestamp(data.get("cached_at", ""))
        entries.append({
            "source": str(data.get("source", "Unknown")),
            "cached_at": timestamp.isoformat() if timestamp else "Invalid",
            "age_seconds": _age_seconds(timestamp) if timestamp else -1,
        })
    return entries


def clear_cache() -> int:
    directory = cache_directory()
    if not directory.is_dir():
        return 0
    removed = 0
    for path in directory.iterdir():
        if path.is_file() and re.fullmatch(r"[a-f0-9]{64}\.json", path.name):
            path.unlink()
            removed += 1
    return removed
