from __future__ import annotations

import logging
from collections import Counter
from concurrent.futures import ProcessPoolExecutor
from itertools import islice
from pathlib import Path
from typing import Iterable, Iterator, TypeVar

from logintel.analysis.engine import AnalysisEngine
from logintel.config import AppConfig
from logintel.correlation.engine import CorrelationEngine
from logintel.enrichment.ioc import IOCExtractor
from logintel.export.writers import ReportExporter
from logintel.ingestion.reader import LogIngestor
from logintel.models import Finding, NormalizedEvent, PipelineSummary, RawLogRecord
from logintel.normalization.normalizer import EventNormalizer
from logintel.parsing.registry import ParserRegistry

LOGGER = logging.getLogger(__name__)
T = TypeVar("T")


class PipelineEngine:
    def __init__(self, config: AppConfig) -> None:
        self.config = config
        self.ingestor = LogIngestor(config.ingestion)
        self.parsers = ParserRegistry()
        self.normalizer = EventNormalizer()
        self.enricher = IOCExtractor()
        self.correlation = CorrelationEngine(config.analysis)
        self.analysis = AnalysisEngine(config.analysis, self.correlation)
        self.exporter = ReportExporter(config.reporting)

    def run(self, input_path: Path, output_dir: Path) -> PipelineSummary:
        LOGGER.info("Iniciando pipeline: input=%s output=%s", input_path, output_dir)
        findings: list[Finding] = []
        timeline: list[NormalizedEvent] = []
        counters: Counter[str] = Counter()
        total_events = 0

        records = self.ingestor.iter_records(input_path)
        for batch in _batched(records, self.config.pipeline.batch_size):
            for event in self._process_batch(batch):
                total_events += 1
                counters[f"parser:{event.parser}"] += 1
                counters[f"type:{event.event_type}"] += 1
                counters[f"severity:{event.severity}"] += 1

                self.correlation.observe(event)
                findings.extend(self.analysis.observe(event))

                if len(timeline) < self.config.pipeline.max_timeline_events:
                    timeline.append(event)

        timeline.sort(key=lambda item: item.timestamp)
        summary = PipelineSummary(total_events=total_events, findings=findings, timeline=timeline, counters=dict(counters))
        self.exporter.export_all(summary, output_dir)
        LOGGER.info("Pipeline finalizado: eventos=%s achados=%s", total_events, len(findings))
        return summary

    def _process_batch(self, batch: list[RawLogRecord]) -> Iterator[NormalizedEvent]:
        if self.config.pipeline.workers > 1 and len(batch) > 1:
            with ProcessPoolExecutor(max_workers=self.config.pipeline.workers) as executor:
                for event in executor.map(_process_record, batch, chunksize=100):
                    if event is not None:
                        yield event
            return

        for record in batch:
            event = _process_record(record)
            if event is not None:
                yield event


def _batched(items: Iterable[T], size: int) -> Iterator[list[T]]:
    iterator = iter(items)
    while True:
        batch = list(islice(iterator, size))
        if not batch:
            break
        yield batch


def _process_record(record: RawLogRecord) -> NormalizedEvent | None:
    parsers = ParserRegistry()
    parsed = parsers.parse(record)
    if parsed is None:
        return None
    event = EventNormalizer().normalize(parsed)
    return IOCExtractor().enrich(event)
