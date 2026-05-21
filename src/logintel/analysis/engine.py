from __future__ import annotations

from logintel.analysis.detectors import BruteForceDetector, SigmaDetector, SpikeDetector, SuspiciousIPDetector
from logintel.config import AnalysisConfig
from logintel.correlation.engine import CorrelationEngine
from logintel.models import Finding, NormalizedEvent


class AnalysisEngine:
    def __init__(self, config: AnalysisConfig, correlation: CorrelationEngine) -> None:
        self.correlation = correlation
        self.brute_force = BruteForceDetector(config)
        self.suspicious_ip = SuspiciousIPDetector(config)
        self.spike = SpikeDetector(config)
        self.sigma = SigmaDetector()

    def observe(self, event: NormalizedEvent) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self.suspicious_ip.observe(event))
        findings.extend(self.spike.observe(event))
        findings.extend(self.sigma.observe(event))
        findings.extend(self.brute_force.evaluate(self.correlation.state))
        return findings
