from __future__ import annotations

import logging

from logintel.models import ParsedEvent, RawLogRecord
from logintel.parsing.base import BaseParser
from logintel.parsing.evtx import EvtxParser
from logintel.parsing.structured import CsvParser, JsonParser, XmlParser
from logintel.parsing.text import ApacheNginxParser, PlainTextParser, SyslogParser

LOGGER = logging.getLogger(__name__)


class ParserRegistry:
    def __init__(self) -> None:
        self.parsers: list[BaseParser] = [
            JsonParser(),
            CsvParser(),
            XmlParser(),
            EvtxParser(),
            ApacheNginxParser(),
            SyslogParser(),
            PlainTextParser(),
        ]

    def parse(self, record: RawLogRecord) -> ParsedEvent | None:
        for parser in self.parsers:
            try:
                if parser.can_parse(record):
                    return parser.parse(record)
            except Exception:
                LOGGER.exception(
                    "Parser %s falhou em %s:%s",
                    parser.name,
                    record.source,
                    record.line_number,
                )
                return ParsedEvent(
                    record.source,
                    record.line_number,
                    "parse_error",
                    {"message": "parse_error", "error_parser": parser.name},
                    record.content,
                )
        return None
