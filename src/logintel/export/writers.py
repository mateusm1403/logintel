from __future__ import annotations

import html
import json
from dataclasses import asdict, is_dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from logintel.config import ReportingConfig
from logintel.models import PipelineSummary


class ReportExporter:
    def __init__(self, config: ReportingConfig) -> None:
        self.config = config

    def export_all(self, summary: PipelineSummary, output_dir: Path) -> None:
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "report.json").write_text(json.dumps(_to_json(summary), indent=2, ensure_ascii=False), encoding="utf-8")
        markdown = self._markdown(summary)
        (output_dir / "report.md").write_text(markdown, encoding="utf-8")
        (output_dir / "report.html").write_text(self._html(markdown), encoding="utf-8")

    def _markdown(self, summary: PipelineSummary) -> str:
        lines = [
            f"# {self.config.title}",
            "",
            f"Analista/Equipe: {self.config.analyst}",
            f"Gerado em: {datetime.utcnow().isoformat()}Z",
            "",
            "## Sumario executivo",
            "",
            f"- Eventos processados: {summary.total_events}",
            f"- Achados identificados: {len(summary.findings)}",
            "",
            "## Contadores principais",
            "",
        ]
        for key, value in sorted(summary.counters.items()):
            lines.append(f"- {key}: {value}")

        lines.extend(["", "## Achados", ""])
        if not summary.findings:
            lines.append("Nenhum achado relevante identificado com as regras atuais.")
        for finding in summary.findings:
            lines.extend(
                [
                    f"### {finding.title}",
                    "",
                    f"- Severidade: {finding.severity}",
                    f"- Descricao: {finding.description}",
                    f"- MITRE ATT&CK: {', '.join(finding.mitre_techniques) if finding.mitre_techniques else 'N/A'}",
                    f"- Sigma: {finding.sigma_rule or 'N/A'}",
                    f"- Evidencia: `{json.dumps(finding.evidence, ensure_ascii=False)}`",
                    "",
                ]
            )

        lines.extend(["## Timeline", ""])
        for event in summary.timeline:
            lines.append(f"- {event.timestamp.isoformat()} | {event.event_type} | {event.src_ip or '-'} | {event.message[:180]}")
        return "\n".join(lines) + "\n"

    def _html(self, markdown: str) -> str:
        body = []
        for line in markdown.splitlines():
            escaped = html.escape(line)
            if line.startswith("# "):
                body.append(f"<h1>{escaped[2:]}</h1>")
            elif line.startswith("## "):
                body.append(f"<h2>{escaped[3:]}</h2>")
            elif line.startswith("### "):
                body.append(f"<h3>{escaped[4:]}</h3>")
            elif line.startswith("- "):
                body.append(f"<p class='bullet'>{escaped}</p>")
            elif not line:
                body.append("")
            else:
                body.append(f"<p>{escaped}</p>")
        return """<!doctype html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8">
  <title>Relatorio de Logs</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 40px; line-height: 1.5; color: #1f2933; }
    h1, h2, h3 { color: #102a43; }
    .bullet { margin-left: 18px; }
    code { background: #f0f4f8; padding: 2px 4px; border-radius: 4px; }
  </style>
</head>
<body>
""" + "\n".join(body) + "\n</body>\n</html>\n"


def _to_json(value: Any) -> Any:
    if is_dataclass(value):
        return {key: _to_json(item) for key, item in asdict(value).items()}
    if isinstance(value, dict):
        return {str(key): _to_json(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_to_json(item) for item in value]
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    return value
