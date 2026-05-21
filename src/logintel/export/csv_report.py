from __future__ import annotations

import html
import json
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any

from logintel.config import ReportingConfig
from logintel.csv_analysis.models import CsvAnalysisSummary


class CsvReportExporter:
    def __init__(self, config: ReportingConfig) -> None:
        self.config = config

    def export_all(self, summary: CsvAnalysisSummary, output_dir: Path) -> None:
        output_dir.mkdir(parents=True, exist_ok=True)
        payload = asdict(summary)
        (output_dir / "csv_report.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        markdown = self._markdown(summary)
        (output_dir / "csv_report.md").write_text(markdown, encoding="utf-8")
        (output_dir / "csv_report.html").write_text(self._html(markdown), encoding="utf-8")

    def _markdown(self, summary: CsvAnalysisSummary) -> str:
        lines = [
            f"# {self.config.title} - Analise CSV",
            "",
            f"Analista/Equipe: {self.config.analyst}",
            f"Fonte: {summary.source_file}",
            f"Gerado em: {datetime.utcnow().isoformat()}Z",
            "",
            "## Sumario executivo",
            "",
            f"- Linhas processadas: {summary.total_rows}",
            f"- Chunks processados: {summary.processed_chunks}",
            f"- Inicio: {summary.time_range.get('start') or 'N/A'}",
            f"- Fim: {summary.time_range.get('end') or 'N/A'}",
            f"- Achados: {len(summary.findings)}",
            "",
            "## Colunas normalizadas",
            "",
        ]
        for original, normalized in summary.normalized_columns.items():
            lines.append(f"- {original} -> {normalized}")

        lines.extend(["", "## Estatisticas", ""])
        for name, values in summary.statistics.items():
            lines.extend([f"### {name}", ""])
            if isinstance(values, dict) and values:
                for key, value in values.items():
                    lines.append(f"- {key}: {value}")
            else:
                lines.append("- Sem dados")
            lines.append("")

        lines.extend(["## Achados", ""])
        if not summary.findings:
            lines.append("Nenhum comportamento suspeito identificado com as regras atuais.")
        for finding in summary.findings:
            lines.extend(
                [
                    f"### {finding.title}",
                    "",
                    f"- Severidade: {finding.severity}",
                    f"- Descricao: {finding.description}",
                    f"- Evidencia: `{json.dumps(finding.evidence, ensure_ascii=False)}`",
                    f"- Recomendacao: {finding.recommendation}",
                    "",
                ]
            )
        return "\n".join(lines) + "\n"

    def _html(self, markdown: str) -> str:
        body: list[str] = []
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
            elif line:
                body.append(f"<p>{escaped}</p>")
        return _html_shell("\n".join(body))


def _html_shell(body: str) -> str:
    return f"""<!doctype html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8">
  <title>Analise CSV de Eventos</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 40px; line-height: 1.5; color: #1f2933; }}
    h1, h2, h3 {{ color: #102a43; }}
    .bullet {{ margin-left: 18px; }}
    code {{ background: #f0f4f8; padding: 2px 4px; border-radius: 4px; }}
  </style>
</head>
<body>
{body}
</body>
</html>
"""


def _to_json(value: Any) -> Any:
    return value
