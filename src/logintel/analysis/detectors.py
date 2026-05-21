from __future__ import annotations

from collections import Counter

from logintel.analysis.mitre import map_mitre
from logintel.analysis.sigma import DEFAULT_SIGMA_RULES
from logintel.config import AnalysisConfig
from logintel.correlation.engine import CorrelationState
from logintel.models import Finding, NormalizedEvent


class BruteForceDetector:
    def __init__(self, config: AnalysisConfig) -> None:
        self.config = config
        self.alerted_ips: set[str] = set()

    def evaluate(self, state: CorrelationState) -> list[Finding]:
        findings: list[Finding] = []
        for ip, events in state.recent_failures.items():
            if ip in self.alerted_ips or len(events) < self.config.brute_force_threshold:
                continue
            self.alerted_ips.add(ip)
            findings.append(
                Finding(
                    title="Possivel brute force",
                    severity="high",
                    description=f"{len(events)} falhas de autenticacao em janela curta para o IP {ip}.",
                    evidence={"src_ip": ip, "failures": len(events), "first_seen": events[0].timestamp.isoformat(), "last_seen": events[-1].timestamp.isoformat()},
                    mitre_techniques=["T1110 - Brute Force"],
                    sigma_rule="Multiple failed authentications from same source",
                )
            )
        return findings


class SuspiciousIPDetector:
    def __init__(self, config: AnalysisConfig) -> None:
        self.config = config
        self.ip_scores: Counter[str] = Counter()
        self.alerted: set[str] = set()

    def observe(self, event: NormalizedEvent) -> list[Finding]:
        if not event.src_ip:
            return []
        score = 0
        if event.status_code in self.config.suspicious_status_codes:
            score += 2
        lower = event.message.lower()
        if any(keyword in lower for keyword in self.config.suspicious_keywords):
            score += 3
        if event.severity in {"high", "critical"}:
            score += 4
        self.ip_scores[event.src_ip] += score

        if self.ip_scores[event.src_ip] >= 10 and event.src_ip not in self.alerted:
            self.alerted.add(event.src_ip)
            return [
                Finding(
                    title="IP suspeito",
                    severity="medium",
                    description=f"IP {event.src_ip} acumulou score suspeito {self.ip_scores[event.src_ip]}.",
                    evidence={"src_ip": event.src_ip, "score": self.ip_scores[event.src_ip], "last_event": event.message},
                    mitre_techniques=map_mitre(event.event_type, event.message),
                )
            ]
        return []


class SpikeDetector:
    def __init__(self, config: AnalysisConfig) -> None:
        self.config = config
        self.buckets: Counter[int] = Counter()
        self.alerted_buckets: set[int] = set()

    def observe(self, event: NormalizedEvent) -> list[Finding]:
        bucket = int(event.timestamp.timestamp()) // self.config.spike_bucket_seconds
        self.buckets[bucket] += 1
        if self.buckets[bucket] < self.config.min_spike_events or bucket in self.alerted_buckets:
            return []
        previous = [count for key, count in self.buckets.items() if key < bucket]
        baseline = (sum(previous) / len(previous)) if previous else 0
        if baseline > 0 and self.buckets[bucket] >= baseline * self.config.spike_multiplier:
            self.alerted_buckets.add(bucket)
            return [
                Finding(
                    title="Pico anormal de eventos",
                    severity="medium",
                    description="Volume de eventos acima do baseline observado.",
                    evidence={"bucket": bucket, "events": self.buckets[bucket], "baseline": round(baseline, 2)},
                )
            ]
        return []


class SigmaDetector:
    def __init__(self) -> None:
        self.rules = DEFAULT_SIGMA_RULES

    def observe(self, event: NormalizedEvent) -> list[Finding]:
        findings: list[Finding] = []
        for rule in self.rules:
            if rule.matches(event):
                findings.append(
                    Finding(
                        title=f"Sigma: {rule.title}",
                        severity=rule.severity,
                        description=f"Evento correspondeu a regra Sigma simplificada: {rule.title}.",
                        evidence={"source": event.source, "message": event.message[:300]},
                        mitre_techniques=map_mitre(event.event_type, event.message),
                        sigma_rule=rule.title,
                    )
                )
        return findings
