from __future__ import annotations

import logging
from pathlib import Path
from typing import Iterable, Iterator

from logintel.config import IngestionConfig
from logintel.models import RawLogRecord

LOGGER = logging.getLogger(__name__)


class LogIngestor:
    def __init__(self, config: IngestionConfig) -> None:
        self.config = config

    def iter_records(self, input_path: Path) -> Iterator[RawLogRecord]:
        for path in self._iter_files(input_path):
            yield from self._read_file(path)

    def _iter_files(self, input_path: Path) -> Iterable[Path]:
        if input_path.is_file():
            yield input_path
            return
        pattern = "**/*" if self.config.recursive else "*"
        for path in input_path.glob(pattern):
            if path.is_file() and path.suffix.lower() in self.config.allowed_extensions:
                yield path

    def _read_file(self, path: Path) -> Iterator[RawLogRecord]:
        hint = path.suffix.lower().lstrip(".") or "txt"
        try:
            if hint == "xml":
                content = path.read_text(encoding="utf-8", errors="replace")
                yield RawLogRecord(path, 1, content, hint)
                return
            if hint == "evtx":
                yield RawLogRecord(path, 1, str(path), hint)
                return
            with path.open("r", encoding="utf-8", errors="replace", newline="") as handle:
                for line_number, line in enumerate(handle, start=1):
                    text = line.rstrip("\n")
                    if text:
                        yield RawLogRecord(path, line_number, text, hint)
        except OSError:
            LOGGER.exception("Falha ao ler arquivo %s", path)
