from __future__ import annotations

import re
from collections.abc import Iterable


CANONICAL_ALIASES = {
    "timestamp": {
        "timestamp",
        "time",
        "_time",
        "@timestamp",
        "eventtime",
        "event_time",
        "date",
        "datetime",
        "created_at",
        "timegenerated",
        "systemtime",
    },
    "src_ip": {
        "src_ip",
        "source_ip",
        "srcip",
        "src",
        "sourceaddress",
        "source_address",
        "client_ip",
        "clientip",
        "remote_ip",
        "ipaddress",
        "source.ip",
        "sourceip",
    },
    "dst_ip": {
        "dst_ip",
        "dest_ip",
        "destination_ip",
        "dstip",
        "destinationaddress",
        "destination_address",
        "server_ip",
        "destination.ip",
    },
    "username": {
        "username",
        "user",
        "account",
        "accountname",
        "targetusername",
        "user.name",
        "principal",
        "actor",
        "src_user",
    },
    "event_type": {
        "event_type",
        "eventtype",
        "event_name",
        "eventname",
        "category",
        "rule",
        "rule_name",
        "signature",
        "alert",
        "operation",
    },
    "severity": {
        "severity",
        "level",
        "risk",
        "priority",
        "alert_severity",
        "rule_level",
    },
    "action": {
        "action",
        "activity",
        "outcome",
        "result",
        "disposition",
        "event.action",
        "status",
    },
    "message": {
        "message",
        "msg",
        "description",
        "event_description",
        "details",
        "raw",
        "_raw",
        "log",
        "event.original",
    },
    "status_code": {
        "status_code",
        "status",
        "http_status",
        "response_code",
        "sc_status",
        "eventid",
        "event_id",
    },
    "host": {
        "host",
        "hostname",
        "computer",
        "computername",
        "agent_name",
        "device_name",
        "host.name",
        "sourcehost",
    },
    "dst_port": {
        "dst_port",
        "destination_port",
        "dest_port",
        "dpt",
        "server_port",
        "destination.port",
    },
}


def normalize_column_name(column: object) -> str:
    text = str(column).strip().lower()
    text = re.sub(r"[^a-z0-9_.]+", "_", text)
    return text.strip("_")


def build_column_mapping(columns: Iterable[object]) -> dict[str, str]:
    mapping: dict[str, str] = {}
    reverse_aliases = {
        alias: canonical
        for canonical, aliases in CANONICAL_ALIASES.items()
        for alias in aliases
    }
    used: set[str] = set()
    for original in columns:
        normalized = normalize_column_name(original)
        canonical = reverse_aliases.get(normalized, normalized)
        target = canonical
        suffix = 2
        while target in used:
            target = f"{canonical}_{suffix}"
            suffix += 1
        mapping[str(original)] = target
        used.add(target)
    return mapping
