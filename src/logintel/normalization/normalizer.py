from __future__ import annotations

import re
from typing import Any

from logintel.models import NormalizedEvent, ParsedEvent
from logintel.utils.time import parse_timestamp

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


class EventNormalizer:
    def normalize(self, parsed: ParsedEvent) -> NormalizedEvent:
        fields = {str(k).lower(): v for k, v in parsed.fields.items()}
        message = str(_first(fields, "message", "msg", "eventdata", "description", default=parsed.raw))
        src_ip = _as_str(_first(fields, "src_ip", "source_ip", "clientip", "ipaddress", "ip"))
        if not src_ip:
            match = IP_RE.search(message) or IP_RE.search(parsed.raw)
            src_ip = match.group(0) if match else None

        status_code = _as_int(_first(fields, "status_code", "status", "sc-status", "col_8"))
        username = _as_str(_first(fields, "username", "user", "accountname", "targetusername"))
        action = _as_str(_first(fields, "action", "method", "eventid"))
        event_type = _event_type(parsed.parser, message, status_code)

        return NormalizedEvent(
            timestamp=parse_timestamp(_first(fields, "timestamp", "time", "@timestamp", "date", "systemtime")),
            source=str(parsed.source),
            event_type=event_type,
            severity=_severity(message, status_code),
            message=message[:1000],
            src_ip=src_ip,
            dst_ip=_as_str(_first(fields, "dst_ip", "destination_ip", "dest_ip")),
            username=username,
            status_code=status_code,
            action=action,
            user_agent=_as_str(_first(fields, "user_agent", "useragent")),
            parser=parsed.parser,
            raw=parsed.raw,
            fields=fields,
        )


def _first(fields: dict[str, Any], *names: str, default: Any = None) -> Any:
    for name in names:
        if name in fields and fields[name] not in (None, ""):
            return fields[name]
    return default


def _as_str(value: Any) -> str | None:
    return None if value in (None, "") else str(value)


def _as_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _event_type(parser: str, message: str, status_code: int | None) -> str:
    lower = message.lower()
    if "failed" in lower or "failure" in lower or status_code in {401, 403}:
        return "authentication_failure"
    if "accepted" in lower or "success" in lower or status_code in {200, 201, 204}:
        return "success"
    if parser == "apache_nginx":
        return "web_access"
    return parser


def _severity(message: str, status_code: int | None) -> str:
    lower = message.lower()
    if any(word in lower for word in ("mimikatz", "ransomware", "malware", "powershell encoded")):
        return "high"
    if status_code in {401, 403, 429, 500} or any(word in lower for word in ("failed", "denied", "invalid")):
        return "medium"
    return "info"
