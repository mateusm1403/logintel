from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from logintel.config import AppConfig, load_config
from logintel.pipeline.engine import PipelineEngine
from logintel.utils.logging_setup import setup_logging


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Processamento massivo de logs para SOC, DFIR e threat hunting."
    )
    parser.add_argument("--input", required=True, help="Arquivo ou diretorio com logs brutos.")
    parser.add_argument("--output", default="output", help="Diretorio de saida dos relatorios.")
    parser.add_argument("--config", default="config/default_config.json", help="Arquivo JSON/YAML de configuracao.")
    parser.add_argument("--log-level", default="INFO", help="Nivel de logging interno.")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    setup_logging(args.log_level)

    config: AppConfig = load_config(Path(args.config))
    engine = PipelineEngine(config)
    summary = engine.run(Path(args.input), Path(args.output))

    print(f"Eventos processados: {summary.total_events}")
    print(f"Achados: {len(summary.findings)}")
    print(f"Relatorios em: {Path(args.output).resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
