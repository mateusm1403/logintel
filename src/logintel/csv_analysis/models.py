from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class CsvFinding:
    title: str
    severity: str
    description: str
    evidence: dict[str, Any]
    recommendation: str


@dataclass(slots=True)
class CsvAnalysisSummary:
    source_file: str
    total_rows: int
    processed_chunks: int
    normalized_columns: dict[str, str]
    time_range: dict[str, str | None]
    statistics: dict[str, Any]
    findings: list[CsvFinding] = field(default_factory=list)
