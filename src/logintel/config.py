from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class PipelineConfig:
    batch_size: int = 5000
    workers: int = 1
    max_timeline_events: int = 1000


@dataclass(slots=True)
class IngestionConfig:
    recursive: bool = True
    allowed_extensions: set[str] = field(
        default_factory=lambda: {".log", ".txt", ".json", ".jsonl", ".csv", ".xml", ".evtx"}
    )


@dataclass(slots=True)
class AnalysisConfig:
    brute_force_window_seconds: int = 300
    brute_force_threshold: int = 5
    spike_bucket_seconds: int = 60
    spike_multiplier: float = 3.0
    min_spike_events: int = 10
    suspicious_status_codes: set[int] = field(default_factory=lambda: {401, 403, 404, 429, 500})
    suspicious_keywords: set[str] = field(
        default_factory=lambda: {"failed", "failure", "denied", "invalid", "malware", "ransomware", "powershell", "mimikatz"}
    )


@dataclass(slots=True)
class ReportingConfig:
    title: str = "Relatorio Tecnico de Analise de Logs"
    analyst: str = "SOC / DFIR Team"


@dataclass(slots=True)
class AppConfig:
    pipeline: PipelineConfig = field(default_factory=PipelineConfig)
    ingestion: IngestionConfig = field(default_factory=IngestionConfig)
    analysis: AnalysisConfig = field(default_factory=AnalysisConfig)
    reporting: ReportingConfig = field(default_factory=ReportingConfig)


def load_config(path: Path) -> AppConfig:
    if not path.exists():
        raise FileNotFoundError(f"Arquivo de configuracao nao encontrado: {path}")

    raw = _load_mapping(path)
    return AppConfig(
        pipeline=PipelineConfig(**raw.get("pipeline", {})),
        ingestion=IngestionConfig(
            recursive=raw.get("ingestion", {}).get("recursive", True),
            allowed_extensions=set(raw.get("ingestion", {}).get("allowed_extensions", [])) or IngestionConfig().allowed_extensions,
        ),
        analysis=AnalysisConfig(
            brute_force_window_seconds=raw.get("analysis", {}).get("brute_force_window_seconds", 300),
            brute_force_threshold=raw.get("analysis", {}).get("brute_force_threshold", 5),
            spike_bucket_seconds=raw.get("analysis", {}).get("spike_bucket_seconds", 60),
            spike_multiplier=raw.get("analysis", {}).get("spike_multiplier", 3.0),
            min_spike_events=raw.get("analysis", {}).get("min_spike_events", 10),
            suspicious_status_codes=set(raw.get("analysis", {}).get("suspicious_status_codes", [401, 403, 404, 429, 500])),
            suspicious_keywords=set(raw.get("analysis", {}).get("suspicious_keywords", [])) or AnalysisConfig().suspicious_keywords,
        ),
        reporting=ReportingConfig(**raw.get("reporting", {})),
    )


def _load_mapping(path: Path) -> dict[str, Any]:
    suffix = path.suffix.lower()
    text = path.read_text(encoding="utf-8")
    if suffix in {".yaml", ".yml"}:
        try:
            import yaml  # type: ignore
        except ImportError as exc:
            raise RuntimeError("Instale PyYAML para usar configuracao YAML.") from exc
        return dict(yaml.safe_load(text) or {})
    return dict(json.loads(text))
