# Arquitetura do LogIntel Pipeline

## Visão geral

O sistema foi separado em camadas pequenas para permitir troca de componentes sem reescrever o pipeline:

* ingestion: descoberta de arquivos e leitura streaming.
* parsing: reconhecimento de formato e conversão para dicionário.
* normalization: criação do modelo canônico NormalizedEvent.
* enrichment: extração de IOCs e metadados.
* correlation: estado incremental por IP, usuário, tipo e janela temporal.
* analysis: detectores, MITRE ATT&CK e regras Sigma simplificadas.
* export: escrita de relatórios em JSON, Markdown e HTML.
* pipeline: orquestração, batching e paralelismo opcional.

O foco da arquitetura é processar milhões de linhas com baixo consumo de memória, usando leitura em streaming, lotes configuráveis, parsers modulares e análises incrementais.

## Capacidades

Ingestão de arquivos grandes sem carregar tudo em memória

Suporte inicial a JSON, CSV, TXT, Syslog, Apache/Nginx, XML e EVTX

Normalização para um modelo comum de eventos

Enriquecimento com extração de IOCs

Correlação temporal e agrupamento por entidades

Detecção de brute force, IPs suspeitos e picos anormais

Timeline de eventos

Mapeamento MITRE ATT&CK simplificado

Base para Sigma rules

Exportação em JSON, Markdown e HTML

PDF planejado para versão futura

## Decisões arquiteturais

Streaming primeiro: arquivos são lidos linha a linha ou por documento, evitando listas gigantes em memória.

Lotes configuráveis: o pipeline processa eventos em batches para equilibrar throughput e memória.

Modelo canônico: todo log vira NormalizedEvent, reduzindo acoplamento entre parser e detector.

Parsers independentes: novos formatos podem ser adicionados sem alterar o pipeline.

Detecções incrementais: detectores usam contadores e janelas pequenas, adequados para grande volume.

Exportadores separados: relatórios podem evoluir sem tocar na lógica de análise.

Dependências mínimas: EVTX usa python-evtx quando instalado; o restante funciona com biblioteca padrão.

## Possíveis gargalos
Regex em linhas muito longas ou formatos não reconhecidos.

Ordenação global de timeline quando o volume for muito alto.

Correlação temporal com janelas grandes demais.

Exportação HTML/Markdown muito extensa para datasets gigantes.

EVTX pode ser mais custoso por exigir parsing estruturado.

## Fluxo de dados

```text
Raw files -> RawLogRecord -> ParsedEvent -> NormalizedEvent -> Findings -> Reports

```

Cada etapa recebe objetos tipados e retorna objetos tipados. Isso reduz hardcode e facilita testes unitários por camada.

## Performance e memória

O ingestor lê arquivos linha a linha para formatos textuais. XML e EVTX exigem cuidado adicional porque podem representar documentos grandes; em produção, a recomendação é quebrar XML grande por evento ou converter EVTX para JSON/XML previamente em workers dedicados.

O batch_size controla quantos registros ficam em memória por vez. A timeline é limitada por max_timeline_events, evitando que o relatório tente carregar todo o dataset.

## Paralelismo

Quando pipeline.workers for maior que 1, o processamento de registros do batch usa ProcessPoolExecutor. Isso ajuda em parsing CPU-bound e regex pesada. Para arquivos pequenos, workers=1 costuma ser mais rápido por evitar overhead de processos.

## Extensão de parsers

Para adicionar um formato:

1. Criar uma classe em src/logintel/parsing/.
2. Herdar de BaseParser.
3. Implementar can_parse e parse.
4. Registrar a classe em ParserRegistry.

## Extensão de detecções

Detectores devem expor observe(event) ou evaluate(state), retornando lista de Finding. Isso permite detecções stateful sem acoplar regras ao pipeline principal.

## Estratégia distribuída futura

Em grande escala, o desenho permite substituir etapas locais por componentes distribuídos:

* Ingestão por Kafka/SQS/RabbitMQ.
* Normalização em workers independentes.
* Estado de correlação em Redis, ClickHouse, Flink ou banco time-series.
* Persistência de eventos em Parquet, DuckDB ou data lake.
* Exportação de achados para SIEM/SOAR.
