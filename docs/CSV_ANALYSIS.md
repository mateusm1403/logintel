# Analise CSV com Pandas

## Comando

```bash
python main.py --csv data/samples/security_events.csv --output output_csv --config config/default_config.json
```

## Fontes esperadas

O modo CSV foi pensado para exports de:

- Wazuh
- Splunk
- SIEMs
- Firewalls
- EDR/XDR
- Windows Events
- Syslog estruturado
- CrowdStrike
- Microsoft Sentinel
- Zabbix
- Elastic Stack

## Normalizacao automatica

O arquivo `src/logintel/csv_analysis/columns.py` mapeia aliases comuns para colunas canonicas:

- `timestamp`
- `src_ip`
- `dst_ip`
- `username`
- `event_type`
- `severity`
- `action`
- `message`
- `status_code`
- `host`
- `dst_port`

Colunas desconhecidas sao preservadas com nome limpo, permitindo expansao futura.

## Analises

O motor usa Pandas para:

- `read_csv` com `chunksize`
- `value_counts`
- `groupby`
- filtros vetorizados
- bucketing temporal com `dt.floor`
- deteccao de brute force por IP, usuario e janela
- deteccao de keywords suspeitas
- identificacao de picos por janela temporal

## Saidas

O relatorio CSV gera:

- `csv_report.json`
- `csv_report.md`
- `csv_report.html`

## Cuidados com grandes datasets

- Aumente `csv_analysis.chunksize` para maior throughput se houver memoria disponivel.
- Reduza `top_n` para relatorios menores.
- Garanta que a coluna temporal esteja em formato parseavel por Pandas.
- Para datasets muito grandes, considere persistir agregados intermediarios em DuckDB, Parquet ou ClickHouse.
