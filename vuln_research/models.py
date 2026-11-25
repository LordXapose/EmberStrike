from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class AssetObservation:
    assessment: str
    scope_notes: str = ""
    asset: str = ""
    port: int | None = None
    protocol: str = ""
    service: str = ""
    product: str = ""
    vendor: str = ""
    version: str = ""
    build: str = ""
    platform: str = ""
    modules: str = ""
    identified_by: str = ""
    confidence: str = "Medium"


@dataclass
class AffectedRange:
    vendor: str = ""
    product: str = ""
    version: str = ""
    start_including: str = ""
    start_excluding: str = ""
    end_including: str = ""
    end_excluding: str = ""

    def label(self) -> str:
        identity = " ".join(part for part in (self.vendor, self.product) if part)
        if self.version and self.version not in ("*", "-"):
            range_text = self.version
        elif any((self.start_including, self.start_excluding, self.end_including, self.end_excluding)):
            lower = f">={self.start_including}" if self.start_including else (
                f">{self.start_excluding}" if self.start_excluding else ""
            )
            upper = f"<={self.end_including}" if self.end_including else (
                f"<{self.end_excluding}" if self.end_excluding else ""
            )
            range_text = " and ".join(part for part in (lower, upper) if part)
        else:
            range_text = "version range not specified"
        return f"{identity} {range_text}".strip()


@dataclass
class Advisory:
    cve_id: str
    title: str
    severity: str = "Unavailable"
    published: str = ""
    updated: str = ""
    description: str = ""
    affected: list[AffectedRange] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    vendor_advisories: list[str] = field(default_factory=list)
    known_exploited: bool = False
    exploitation_note: str = ""
    remediation: str = ""
    sources: list[str] = field(default_factory=list)


@dataclass
class PossibleMatch:
    advisory: Advisory
    confidence: str
    why_match: list[str]
    missing_evidence: list[str]
    conflicting_evidence: list[str]


@dataclass
class ResearchReport:
    asset: AssetObservation
    matches: list[PossibleMatch]
    source_warnings: list[str] = field(default_factory=list)
    offline: bool = False
    hidden_severity_matches: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
