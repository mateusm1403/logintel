from __future__ import annotations

from dataclasses import dataclass

from logintel.models import NormalizedEvent


@dataclass(slots=True)
class SigmaRule:
    title: str
    field: str
    contains: str
    severity: str

    def matches(self, event: NormalizedEvent) -> bool:
        value = getattr(event, self.field, None)
        return value is not None and self.contains.lower() in str(value).lower()


DEFAULT_SIGMA_RULES = [
    SigmaRule("Suspicious PowerShell Usage", "message", "powershell", "high"),
    SigmaRule("Credential Dumping Keyword", "message", "mimikatz", "critical"),
    SigmaRule("Repeated Access Denied", "message", "denied", "medium"),
]
