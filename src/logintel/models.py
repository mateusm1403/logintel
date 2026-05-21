from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class RawLogRecord:
    source: Path
    line_number: int
    content: str
    format_hint: str


@dataclass(slots=True)
class ParsedEvent:
    source: Path
    line_number: int
    parser: str
    fields: dict[str, Any]
    raw: str


@dataclass(slots=True)
class NormalizedEvent:
    timestamp: datetime
    source: str
    event_type: str
    severity: str
    message: str
    src_ip: str | None = None
    dst_ip: str | None = None
    username: str | None = None
    status_code: int | None = None
    action: str | None = None
    user_agent: str | None = None
    parser: str = "unknown"
    raw: str = ""
    fields: dict[str, Any] = field(default_factory=dict)
    iocs: dict[str, list[str]] = field(default_factory=dict)

    @staticmethod
    def fallback(source: str, message: str, raw: str) -> "NormalizedEvent":
        return NormalizedEvent(
            timestamp=datetime.now(timezone.utc),
            source=source,
            event_type="unknown",
            severity="info",
            message=message[:500],
            raw=raw,
        )


@dataclass(slots=True)
class Finding:
    title: str
    severity: str
    description: str
    evidence: dict[str, Any]
    mitre_techniques: list[str] = field(default_factory=list)
    sigma_rule: str | None = None


@dataclass(slots=True)
class PipelineSummary:
    total_events: int
    findings: list[Finding]
    timeline: list[NormalizedEvent]
    counters: dict[str, int]
