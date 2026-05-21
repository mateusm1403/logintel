from __future__ import annotations

from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field

from logintel.config import AnalysisConfig
from logintel.models import NormalizedEvent


@dataclass(slots=True)
class CorrelationState:
    by_src_ip: Counter[str] = field(default_factory=Counter)
    by_username: Counter[str] = field(default_factory=Counter)
    by_event_type: Counter[str] = field(default_factory=Counter)
    recent_failures: dict[str, deque[NormalizedEvent]] = field(default_factory=lambda: defaultdict(deque))


class CorrelationEngine:
    def __init__(self, config: AnalysisConfig) -> None:
        self.config = config
        self.state = CorrelationState()

    def observe(self, event: NormalizedEvent) -> None:
        self.state.by_event_type[event.event_type] += 1
        if event.src_ip:
            self.state.by_src_ip[event.src_ip] += 1
        if event.username:
            self.state.by_username[event.username] += 1

        if event.event_type == "authentication_failure" and event.src_ip:
            bucket = self.state.recent_failures[event.src_ip]
            bucket.append(event)
            cutoff = event.timestamp.timestamp() - self.config.brute_force_window_seconds
            while bucket and bucket[0].timestamp.timestamp() < cutoff:
                bucket.popleft()
