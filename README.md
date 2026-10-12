# Honeypot

An AI-powered honeypot platform that captures real-world attacks, enriches them with threat intelligence, and uses machine learning to flag anomalous behavior. Cowrie (SSH/Telnet) and Dionaea (malware-oriented) honeypots feed an Elastic Stack pipeline, while per-honeypot Isolation Forest models score each event and surface suspicious activity in Kibana.

## Overview

Network honeypots attract attackers and record their activity. Logs are forwarded to Elasticsearch through Filebeat and visualized in Kibana. In parallel, raw events are turned into behavioral features and scored by an Isolation Forest model to detect abnormal attack patterns automatically. For Dionaea, captured malware hashes are checked against VirusTotal to spot potential zero-day samples.

## Features

- **Two honeypots**: Cowrie (SSH/Telnet brute-force and shell sessions) and Dionaea (exploit and malware capture)
- **Centralized log collection** with Filebeat, indexed in Elasticsearch
- **Kibana dashboards** for attack visualization, ready to import
- **Dedicated ML pipelines** per honeypot: feature extraction, scaling, training, prediction
- **Anomaly detection** with Isolation Forest, producing predictions and JSONL alerts
- **Zero-day hunting** (Dionaea) using VirusTotal lookups
- **Cloud deployment** on AWS EC2, with Docker Compose for the Elastic Stack

## Architecture

```
Internet
   │
   ▼
Honeypots (Cowrie, Dionaea)
   │
   ├──► Filebeat ──► Elasticsearch ──► Kibana dashboards
   │
   ▼
Raw logs (CSV)
   │
   ▼
Feature extraction + scaling
   │
   ▼
Isolation Forest (one model per honeypot)
   │
   ├──► Predictions / alerts ──► Elasticsearch ──► Kibana
   │
   └──► VirusTotal lookup (zero-day detection)
```

## Tech Stack

| Category | Technologies |
|----------|--------------|
| Language | Python |
| Honeypots | Cowrie, Dionaea |
| Log collection | Filebeat |
| Storage & visualization | Elasticsearch, Kibana |
| Machine learning | scikit-learn (Isolation Forest), pandas, NumPy |
| Threat intelligence | VirusTotal API |
| Infrastructure | Docker Compose, AWS EC2 |

## Machine Learning Pipeline

1. Collect raw events from the honeypots.
2. Extract behavioral features (`features.py`).
3. Scale the features and save the scaler.
4. Train an Isolation Forest (`model.py`).
5. Score new events and generate alerts (`predict.py`).
6. Push results to Elasticsearch (`push_to_elastic.py`) and explore them in Kibana.

## Project Structure

```
honeypot/
├── data/
│   ├── cowrie/                  # raw, processed, predictions, alerts
│   └── dionaea/                 # raw, processed, predictions, alerts, VirusTotal results
├── docker/
│   └── docker-compose.yml       # Elastic Stack
├── kibana/
│   ├── import_dashboards.sh     # dashboard import script
│   └── dashboards_export.ndjson # exported Kibana dashboards
├── models/
│   ├── cowrie/                  # model, scaler, feature columns
│   └── dionaea/                 # model, scaler, feature columns, anomaly threshold
├── src/
│   ├── cowrie/
│   │   ├── features.py
│   │   ├── model.py
│   │   ├── predict.py
│   │   └── push_to_elastic.py
│   └── dionaea/
│       ├── features.py
│       ├── model.py
│       ├── predict.py
│       ├── virustotal_client.py
│       ├── zero_day_hunter.py
│       ├── push_virustotal_results.py
│       ├── push_zeroday.py
│       └── push_to_elastic.py
├── fetch_logs.py                # log retrieval from the honeypot server
├── requirements.txt
└── README.md
```

## Getting Started

### Prerequisites

- Python 3.9+
- Docker and Docker Compose
- A VirusTotal API key (for zero-day detection)

### Clone the repository

```bash
git clone https://github.com/HajarBenbounjima04/honeypot.git
cd honeypot
```

### Install dependencies

```bash
pip install -r requirements.txt
```

### Configure

Never commit secrets. Export your VirusTotal key as an environment variable:

```bash
export VT_API_KEY="your_api_key"
```

### Start the Elastic Stack

```bash
cd docker
docker compose up -d
cd ..
bash kibana/import_dashboards.sh
```

### Run the pipelines

```bash
# Fetch logs from the honeypot server
python fetch_logs.py

# Cowrie
python src/cowrie/features.py
python src/cowrie/model.py
python src/cowrie/predict.py
python src/cowrie/push_to_elastic.py

# Dionaea
python src/dionaea/features.py
python src/dionaea/model.py
python src/dionaea/predict.py
python src/dionaea/zero_day_hunter.py
python src/dionaea/push_virustotal_results.py
python src/dionaea/push_zeroday.py
python src/dionaea/push_to_elastic.py
```

## Learning Objectives

This project demonstrates practical experience with:

- Cybersecurity monitoring and honeypot deployment
- Threat intelligence (VirusTotal enrichment)
- Log aggregation and analysis with the ELK Stack
- Machine learning for anomaly detection
- AWS cloud deployment

## Disclaimer

This project is for research and educational purposes. Deploy honeypots only in isolated, controlled environments.
