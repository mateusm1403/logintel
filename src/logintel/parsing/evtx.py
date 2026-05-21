from __future__ import annotations

import logging
from pathlib import Path

from logintel.models import ParsedEvent, RawLogRecord
from logintel.parsing.base import BaseParser

LOGGER = logging.getLogger(__name__)


class EvtxParser(BaseParser):
    name = "evtx"

    def can_parse(self, record: RawLogRecord) -> bool:
        return record.format_hint == "evtx"

    def parse(self, record: RawLogRecord) -> ParsedEvent | None:
        # EVTX e um formato binario. Para escala, recomenda-se converter cada
        # evento em XML/JSON em um worker dedicado antes da normalizacao.
        path = Path(record.content)
        try:
            from Evtx.Evtx import Evtx  # type: ignore
        except ImportError:
            LOGGER.warning("python-evtx nao instalado; emitindo placeholder para %s", path)
            return ParsedEvent(record.source, record.line_number, self.name, {"message": f"EVTX file detected: {path}"}, record.content)

        events: list[str] = []
        with Evtx(str(path)) as log:
            for event in log.records():
                events.append(event.xml())
                if len(events) >= 100:
                    break
        return ParsedEvent(record.source, record.line_number, self.name, {"message": "EVTX parsed", "events_preview": events}, record.content)
