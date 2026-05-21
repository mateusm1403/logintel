from __future__ import annotations

import logging
from collections import Counter
from dataclasses import asdict
from pathlib import Path
from typing import Any

import pandas as pd

from logintel.config import CsvAnalysisConfig, ReportingConfig
from logintel.csv_analysis.columns import build_column_mapping
from logintel.csv_analysis.models import CsvAnalysisSummary, CsvFinding
from logintel.export.csv_report import CsvReportExporter

LOGGER = logging.getLogger(__name__)


class CsvAnalysisEngine:
    def __init__(self, config: CsvAnalysisConfig, reporting: ReportingConfig) -> None:
        self.config = config
        self.exporter = CsvReportExporter(reporting)

    def run(self, csv_path: Path, output_dir: Path) -> CsvAnalysisSummary:
        if not csv_path.exists():
            raise FileNotFoundError(f"CSV nao encontrado: {csv_path}")

        LOGGER.info("Iniciando analise CSV com Pandas: %s", csv_path)
        state = _CsvState(self.config)
        mapping: dict[str, str] = {}

        reader = pd.read_csv(
            csv_path,
            chunksize=self.config.chunksize,
            dtype="string",
            low_memory=False,
            encoding_errors="replace",
        )
        for chunk_number, chunk in enumerate(reader, start=1):
            if not mapping:
                mapping = build_column_mapping(chunk.columns)
            normalized = _normalize_chunk(chunk, mapping)
            state.observe(normalized)
            LOGGER.info("Chunk CSV processado: chunk=%s linhas=%s", chunk_number, len(normalized))

        summary = state.to_summary(csv_path, mapping)
        self.exporter.export_all(summary, output_dir)
        LOGGER.info("Analise CSV finalizada: linhas=%s achados=%s", summary.total_rows, len(summary.findings))
        return summary


class _CsvState:
    def __init__(self, config: CsvAnalysisConfig) -> None:
        self.config = config
        self.total_rows = 0
        self.processed_chunks = 0
        self.min_timestamp: pd.Timestamp | None = None
        self.max_timestamp: pd.Timestamp | None = None
        self.event_types: Counter[str] = Counter()
        self.severities: Counter[str] = Counter()
        self.actions: Counter[str] = Counter()
        self.src_ips: Counter[str] = Counter()
        self.dst_ips: Counter[str] = Counter()
        self.users: Counter[str] = Counter()
        self.hosts: Counter[str] = Counter()
        self.status_codes: Counter[str] = Counter()
        self.keyword_hits: Counter[str] = Counter()
        self.time_buckets: Counter[str] = Counter()
        self.brute_force_candidates: Counter[tuple[str, str, str]] = Counter()
        self.findings: list[CsvFinding] = []

    def observe(self, frame: pd.DataFrame) -> None:
        self.total_rows += len(frame)
        self.processed_chunks += 1
        if frame.empty:
            return

        timestamps = _coerce_timestamps(frame)
        self._observe_time(timestamps)
        self._update_counter(self.event_types, frame, "event_type")
        self._update_counter(self.severities, frame, "severity")
        self._update_counter(self.actions, frame, "action")
        self._update_counter(self.src_ips, frame, "src_ip")
        self._update_counter(self.dst_ips, frame, "dst_ip")
        self._update_counter(self.users, frame, "username")
        self._update_counter(self.hosts, frame, "host")
        self._update_counter(self.status_codes, frame, "status_code")
        self._observe_keywords(frame)
        self._observe_brute_force(frame, timestamps)

    def to_summary(self, csv_path: Path, mapping: dict[str, str]) -> CsvAnalysisSummary:
        self._finalize_findings()
        return CsvAnalysisSummary(
            source_file=str(csv_path),
            total_rows=self.total_rows,
            processed_chunks=self.processed_chunks,
            normalized_columns=mapping,
            time_range={
                "start": _timestamp_to_str(self.min_timestamp),
                "end": _timestamp_to_str(self.max_timestamp),
            },
            statistics={
                "top_event_types": _counter_top(self.event_types, self.config.top_n),
                "top_severities": _counter_top(self.severities, self.config.top_n),
                "top_actions": _counter_top(self.actions, self.config.top_n),
                "top_src_ips": _counter_top(self.src_ips, self.config.top_n),
                "top_dst_ips": _counter_top(self.dst_ips, self.config.top_n),
                "top_users": _counter_top(self.users, self.config.top_n),
                "top_hosts": _counter_top(self.hosts, self.config.top_n),
                "top_status_codes": _counter_top(self.status_codes, self.config.top_n),
                "keyword_hits": _counter_top(self.keyword_hits, self.config.top_n),
                "event_volume_by_time": _counter_top(self.time_buckets, self.config.top_n),
            },
            findings=self.findings,
        )

    def _observe_time(self, timestamps: pd.Series) -> None:
        valid = timestamps.dropna()
        if valid.empty:
            return
        chunk_min = valid.min()
        chunk_max = valid.max()
        self.min_timestamp = chunk_min if self.min_timestamp is None else min(self.min_timestamp, chunk_min)
        self.max_timestamp = chunk_max if self.max_timestamp is None else max(self.max_timestamp, chunk_max)
        buckets = valid.dt.floor(self.config.timestamp_bucket).astype("string").value_counts()
        self.time_buckets.update(_series_counter_items(buckets))

    def _observe_keywords(self, frame: pd.DataFrame) -> None:
        text = _text_blob(frame)
        if text.empty:
            return
        lower = text.str.lower()
        for keyword in self.config.suspicious_keywords:
            hits = int(lower.str.contains(keyword, regex=False, na=False).sum())
            if hits:
                self.keyword_hits[keyword] += hits

    def _observe_brute_force(self, frame: pd.DataFrame, timestamps: pd.Series) -> None:
        if "src_ip" not in frame.columns:
            return
        working = frame.copy()
        working["_timestamp"] = timestamps
        failure_mask = _failure_mask(working)
        failures = working.loc[failure_mask & working["_timestamp"].notna()].copy()
        if failures.empty:
            return
        failures["_window"] = failures["_timestamp"].dt.floor(self.config.brute_force_window).astype("string")
        if "username" not in failures.columns:
            failures["username"] = "-"
        grouped = failures.groupby(["src_ip", "username", "_window"], dropna=True).size()
        for key, count in grouped.items():
            self.brute_force_candidates[(str(key[0]), str(key[1]), str(key[2]))] += int(count)

    def _finalize_findings(self) -> None:
        for (src_ip, username, window), count in self.brute_force_candidates.items():
            if count >= self.config.brute_force_threshold:
                self.findings.append(
                    CsvFinding(
                        title="Possivel brute force em CSV",
                        severity="high",
                        description=f"{count} falhas observadas para origem {src_ip} na janela {window}.",
                        evidence={"src_ip": src_ip, "username": username, "window": window, "failures": count},
                        recommendation="Validar origem, usuario alvo, sucesso posterior e aplicar bloqueio/contencao se confirmado.",
                    )
                )

        for keyword, count in self.keyword_hits.most_common(self.config.top_n):
            if count:
                self.findings.append(
                    CsvFinding(
                        title=f"Keyword suspeita: {keyword}",
                        severity="medium",
                        description=f"A keyword '{keyword}' apareceu {count} vezes no dataset.",
                        evidence={"keyword": keyword, "count": count},
                        recommendation="Revisar eventos associados e cruzar com host, usuario, processo e endereco IP.",
                    )
                )

        if self.time_buckets:
            counts = list(self.time_buckets.values())
            baseline = sum(counts) / len(counts)
            for bucket, count in self.time_buckets.items():
                if baseline > 0 and count >= baseline * 3 and count >= 10:
                    self.findings.append(
                        CsvFinding(
                            title="Pico anormal de eventos em CSV",
                            severity="medium",
                            description="Uma janela temporal apresentou volume muito acima da media do arquivo.",
                            evidence={"bucket": bucket, "events": count, "baseline": round(baseline, 2)},
                            recommendation="Investigar eventos dessa janela e comparar com mudancas operacionais conhecidas.",
                        )
                    )

    @staticmethod
    def _update_counter(counter: Counter[str], frame: pd.DataFrame, column: str) -> None:
        if column not in frame.columns:
            return
        values = frame[column].dropna().astype("string")
        values = values[values.str.len() > 0]
        counter.update(_series_counter_items(values.value_counts()))


def _normalize_chunk(chunk: pd.DataFrame, mapping: dict[str, str]) -> pd.DataFrame:
    frame = chunk.rename(columns=mapping).copy()
    for column in frame.columns:
        if frame[column].dtype == "string":
            frame[column] = frame[column].str.strip()
    return frame


def _coerce_timestamps(frame: pd.DataFrame) -> pd.Series:
    if "timestamp" not in frame.columns:
        return pd.Series(pd.NaT, index=frame.index, dtype="datetime64[ns, UTC]")
    return pd.to_datetime(frame["timestamp"], errors="coerce", utc=True)


def _text_blob(frame: pd.DataFrame) -> pd.Series:
    candidates = [column for column in ("message", "event_type", "action", "severity") if column in frame.columns]
    if not candidates:
        return pd.Series("", index=frame.index, dtype="string")
    return frame[candidates].fillna("").astype("string").agg(" ".join, axis=1)


def _failure_mask(frame: pd.DataFrame) -> pd.Series:
    text = _text_blob(frame).str.lower()
    mask = text.str.contains("failed|failure|denied|invalid|blocked|unauthorized|4625|401|403", regex=True, na=False)
    if "status_code" in frame.columns:
        mask = mask | frame["status_code"].astype("string").isin(["401", "403", "4625"])
    return mask


def _series_counter_items(series: pd.Series) -> dict[str, int]:
    return {str(key): int(value) for key, value in series.items() if str(key) not in {"", "<NA>", "nan", "NaT"}}


def _counter_top(counter: Counter[str], top_n: int) -> dict[str, int]:
    return dict(counter.most_common(top_n))


def _timestamp_to_str(value: pd.Timestamp | None) -> str | None:
    if value is None or pd.isna(value):
        return None
    return value.isoformat()


def summary_to_dict(summary: CsvAnalysisSummary) -> dict[str, Any]:
    return asdict(summary)
