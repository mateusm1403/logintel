# Arquitetura do LogIntel Pipeline

## Visao geral

O sistema foi separado em camadas pequenas para permitir troca de componentes sem reescrever o pipeline:

- `ingestion`: descoberta de arquivos e leitura streaming.
- `parsing`: reconhecimento de formato e conversao para dicionario.
- `normalization`: criacao do modelo canonico `NormalizedEvent`.
- `enrichment`: extracao de IOCs e metadados.
- `correlation`: estado incremental por IP, usuario, tipo e janela temporal.
- `analysis`: detectores, MITRE ATT&CK e regras Sigma simplificadas.
- `export`: escrita de relatorios em JSON, Markdown e HTML.
- `pipeline`: orquestracao, batching e paralelismo opcional.

## Fluxo de dados

```text
Raw files -> RawLogRecord -> ParsedEvent -> NormalizedEvent -> Findings -> Reports
```

Cada etapa recebe objetos tipados e retorna objetos tipados. Isso reduz hardcode e facilita testes unitarios por camada.

## Performance e memoria

O ingestor le arquivos linha a linha para formatos textuais. XML e EVTX exigem cuidado adicional porque podem representar documentos grandes; em producao, a recomendacao e quebrar XML grande por evento ou converter EVTX para JSON/XML previamente em workers dedicados.

O `batch_size` controla quantos registros ficam em memoria por vez. A timeline e limitada por `max_timeline_events`, evitando que o relatorio tente carregar todo o dataset.

## Paralelismo

Quando `pipeline.workers` for maior que 1, o processamento de registros do batch usa `ProcessPoolExecutor`. Isso ajuda em parsing CPU-bound e regex pesada. Para arquivos pequenos, `workers=1` costuma ser mais rapido por evitar overhead de processos.

## Extensao de parsers

Para adicionar um formato:

1. Criar uma classe em `src/logintel/parsing/`.
2. Herdar de `BaseParser`.
3. Implementar `can_parse` e `parse`.
4. Registrar a classe em `ParserRegistry`.

## Extensao de deteccoes

Detectores devem expor `observe(event)` ou `evaluate(state)`, retornando lista de `Finding`. Isso permite deteccoes stateful sem acoplar regras ao pipeline principal.

## Estrategia distribuida futura

Em grande escala, o desenho permite substituir etapas locais por componentes distribuidos:

- Ingestao por Kafka/SQS/RabbitMQ.
- Normalizacao em workers independentes.
- Estado de correlacao em Redis, ClickHouse, Flink ou banco time-series.
- Persistencia de eventos em Parquet, DuckDB ou data lake.
- Exportacao de achados para SIEM/SOAR.
