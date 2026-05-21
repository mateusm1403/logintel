from __future__ import annotations

import re

from logintel.models import ParsedEvent, RawLogRecord
from logintel.parsing.base import BaseParser


APACHE_RE = re.compile(
    r'(?P<src_ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) (?P<protocol>[^"]+)" '
    r"(?P<status_code>\d{3}) (?P<bytes>\S+)(?: \"(?P<referrer>[^\"]*)\" \"(?P<user_agent>[^\"]*)\")?"
)

SYSLOG_RE = re.compile(
    r"(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) (?P<process>[^:]+): (?P<message>.*)"
)

KEY_VALUE_RE = re.compile(r"(?P<key>[A-Za-z0-9_.-]+)=(?P<value>\"[^\"]+\"|\S+)")


class ApacheNginxParser(BaseParser):
    name = "apache_nginx"

    def can_parse(self, record: RawLogRecord) -> bool:
        return bool(APACHE_RE.match(record.content))

    def parse(self, record: RawLogRecord) -> ParsedEvent | None:
        match = APACHE_RE.match(record.content)
        if not match:
            return None
        fields = match.groupdict()
        fields["message"] = f"{fields.get('method')} {fields.get('path')} {fields.get('status_code')}"
        return ParsedEvent(record.source, record.line_number, self.name, fields, record.content)


class SyslogParser(BaseParser):
    name = "syslog"

    def can_parse(self, record: RawLogRecord) -> bool:
        return bool(SYSLOG_RE.match(record.content))

    def parse(self, record: RawLogRecord) -> ParsedEvent | None:
        match = SYSLOG_RE.match(record.content)
        if not match:
            return None
        fields = match.groupdict()
        fields.update(_extract_key_values(fields.get("message", "")))
        return ParsedEvent(record.source, record.line_number, self.name, fields, record.content)


class PlainTextParser(BaseParser):
    name = "txt"

    def can_parse(self, record: RawLogRecord) -> bool:
        return True

    def parse(self, record: RawLogRecord) -> ParsedEvent | None:
        fields = {"message": record.content}
        fields.update(_extract_key_values(record.content))
        return ParsedEvent(record.source, record.line_number, self.name, fields, record.content)


def _extract_key_values(message: str) -> dict[str, str]:
    extracted: dict[str, str] = {}
    for match in KEY_VALUE_RE.finditer(message):
        value = match.group("value").strip('"')
        extracted[match.group("key")] = value
    return extracted
