from __future__ import annotations

import re

from logintel.models import NormalizedEvent


IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
URL_RE = re.compile(r"https?://[^\s\"']+")
HASH_RE = re.compile(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b")


class IOCExtractor:
    def enrich(self, event: NormalizedEvent) -> NormalizedEvent:
        blob = f"{event.message} {event.raw}"
        event.iocs = {
            "ips": sorted(set(IP_RE.findall(blob))),
            "domains": sorted(set(DOMAIN_RE.findall(blob))),
            "urls": sorted(set(URL_RE.findall(blob))),
            "hashes": sorted(set(HASH_RE.findall(blob))),
        }
        return event
