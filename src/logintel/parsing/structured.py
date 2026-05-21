from __future__ import annotations

import csv
import json
import xml.etree.ElementTree as ET
from io import StringIO

from logintel.models import ParsedEvent, RawLogRecord
from logintel.parsing.base import BaseParser


class JsonParser(BaseParser):
    name = "json"

    def can_parse(self, record: RawLogRecord) -> bool:
        return record.format_hint in {"json", "jsonl"} or record.content.lstrip().startswith("{")

    def parse(self, record: RawLogRecord) -> ParsedEvent | None:
        data = json.loads(record.content)
        if not isinstance(data, dict):
            data = {"message": data}
        return ParsedEvent(record.source, record.line_number, self.name, data, record.content)


class CsvParser(BaseParser):
    name = "csv"

    def can_parse(self, record: RawLogRecord) -> bool:
        return record.format_hint == "csv"

    def parse(self, record: RawLogRecord) -> ParsedEvent | None:
        reader = csv.reader(StringIO(record.content))
        row = next(reader, [])
        fields = {f"col_{index}": value for index, value in enumerate(row)}
        return ParsedEvent(record.source, record.line_number, self.name, fields, record.content)


class XmlParser(BaseParser):
    name = "xml"

    def can_parse(self, record: RawLogRecord) -> bool:
        return record.format_hint == "xml" or record.content.lstrip().startswith("<")

    def parse(self, record: RawLogRecord) -> ParsedEvent | None:
        root = ET.fromstring(record.content)
        fields: dict[str, object] = {"root": _strip_ns(root.tag)}
        for elem in root.iter():
            tag = _strip_ns(elem.tag)
            if elem.text and elem.text.strip():
                fields[tag] = elem.text.strip()
            for key, value in elem.attrib.items():
                fields[f"{tag}.{key}"] = value
        return ParsedEvent(record.source, record.line_number, self.name, fields, record.content[:2000])


def _strip_ns(tag: str) -> str:
    return tag.split("}", 1)[-1]
