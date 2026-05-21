# LogIntel

![Python](https://img.shields.io/badge/python-3.11+-blue)
![Status](https://img.shields.io/badge/status-active-success)
![License](https://img.shields.io/badge/license-MIT-green)

Pipeline de alta performance em Python para processamento massivo e streaming de logs. Projetado com arquitetura modular para SOC, DFIR e Threat Hunting, focado em baixo consumo de memória, normalização de dados e detecção de ameaças.

# Motivação

Durante análises de segurança e troubleshooting, lidar com grandes volumes de logs normalmente exige múltiplas ferramentas e muito processamento manual.

O objetivo do LogIntel Pipeline é simplificar esse fluxo, oferecendo uma base modular e escalável para ingestão, normalização, correlação e análise de eventos.

---

# Features

- Processamento massivo de logs
- Leitura em streaming
- Parsers modulares
- Normalização de eventos
- Correlação temporal
- Extração de IOCs
- Detecção de brute force
- Identificação de IPs suspeitos
- Timeline de eventos
- Exportação em JSON, Markdown e HTML
- Estrutura compatível com MITRE ATT&CK
- Base para integração com Sigma Rules

---

# Formatos Suportados

- JSON / JSONL
- CSV
- TXT
- Syslog
- Apache Logs
- Nginx Logs
- XML
- EVTX

---

# Estrutura do Projeto

```text
.
├── config/
│   └── default_config.json
├── data/
│   └── samples/
├── docs/
│   └── architecture.md
├── reports/
│   └── templates/
├── src/
│   └── logintel/
│       ├── analysis/
│       ├── correlation/
│       ├── enrichment/
│       ├── export/
│       ├── ingestion/
│       ├── normalization/
│       ├── parsing/
│       ├── pipeline/
│       └── utils/
├── output/
├── tests/
├── main.py
└── requirements.txt
```

# Instalação

Clone o repositório
git clone https://github.com/mateusm1403/logintel-pipeline.git

cd logintel-pipeline

Instale as dependências
pip install -r requirements.txt

# Uso Rápido

Crie e ative o ambiente virtual

1. Windows (PowerShell)
python -m venv .venv
.venv\Scripts\activate

2. Linux / WSL
python3 -m venv .venv
source .venv/bin/activate

Crie um arquivo de log para teste

1. Windows
echo Failed password for root from 10.0.0.1 > logs.txt

2. Linux / WSL
echo "Failed password for root from 10.0.0.1" > logs.txt

Execute o pipeline
python main.py --input logs.txt

Exemplo de saída
INFO logintel.pipeline.engine - Iniciando pipeline
INFO logintel.pipeline.engine - Pipeline finalizado

Eventos processados: 13
Achados: 0
Relatorios em: output/

Executando com diretórios inteiros

Também é possível processar múltiplos logs:

python main.py --input ./data

Parâmetros disponíveis
Argumento	Descrição
--input	Arquivo ou diretório contendo logs
--output	Diretório de saída dos relatórios
--config	Arquivo de configuração JSON/YAML
--log-level	Nível de logging (INFO, DEBUG, ERROR)

Exemplo completo
python main.py ^
  --input logs.txt ^
  --output output ^
  --config config/default_config.json ^
  --log-level INFO

Linux/WSL:

python3 main.py \
  --input logs.txt \
  --output output \
  --config config/default_config.json \
  --log-level INFO

Pipeline de Processamento

O fluxo principal segue as seguintes etapas:

Ingestão
Parsing
Normalização
Enriquecimento
Correlação
Análise
Exportação
Exemplo de Detecções
Tentativas de brute force
Picos anormais de autenticação
IPs suspeitos
Correlação temporal
Extração de IOCs
Eventos agrupados por entidade

# Desenvolvimento

Recomendado:

Python 3.11 ou 3.12 (apenas por questão de estabilidade, você pode testar em outras versões)
VSCode + extensão Python
Ambiente virtual (venv) isolado
