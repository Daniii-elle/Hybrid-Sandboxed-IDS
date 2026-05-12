# Hybrid Sandboxed Intrusion Detection Framework for Zero-Day Threats in Smart Grid Systems

**Author:** Danielle Mbala Erusiafe (`2023/A/CYB/0065`)  
**Supervisor:** Prof. Wilson Nwankwo  
**Institution:** Department of Cyber Security, School of Computing, Miva Open University, Abuja, Nigeria  
**Submitted:** April 2026  
**Contact:** danielle.erusiafe@miva.edu.ng

---

## Overview

This project implements a three-layer hybrid Intrusion Detection System (IDS) designed specifically for smart grid environments. The system combines:

- **Signature-based detection** via Suricata. It is fast, has a high detection of known threats
- **Anomaly-based detection** via Isolation Forest (scikit-learn). Statistical deviation detection for zero-day-like behaviour
- **Dynamic sandbox analysis** via Docker + VirusTotal API. Analyzes behaviors of suspicious payloads.

Network traffic, alerts, and sandbox results are sent to the **ELK Stack** (Elasticsearch, Logstash, Kibana) for real-time monitoring and visualisation.

The framework targets zero-day threats in smart grid infrastructure and is evaluated against ten controlled attack scenarios covering SCADA/ICS protocols (Modbus, DNP3, IEC 61850).

---

## Repository Structure

```
Hybrid-Sandboxed-IDS-for-Zero-Day-Threats-in-Smart-Grids/
│
├── sandbox/                        # Docker sandbox environment
│   ├── Dockerfile                  # Container definition for isolated execution
│   ├── runner.py                   # Sandbox execution and behavioural monitoring logic
│   └── virustotal_api.py           # VirusTotal & Hybrid Analysis API client
│
├── suricata-config/                # Suricata IDS configuration files
│   ├── suricata.yaml               # Main Suricata configuration
│   ├── classification.config       # Alert classification definitions
│   ├── reference.config            # Reference URL mappings
│   ├── threshold.config            # Alert suppression and thresholds
│   └── update.yaml                 # Rule update configuration
│
├── ids_full_system.py              # Main IDS pipeline (train → monitor → alert → sandbox → ELK)
├── elk_api.py                      # ELK Stack API client (index management, search, health)
├── test_attack_generator.py        # Live attack simulation script (10 smart grid scenarios)
├── log_generator.py                # Synthetic normal traffic log generator
├── setup_elk.py                    # ELK index initialisation helper
├── setup_sandbox.py                # Docker sandbox setup and verification
├── email_reporter.py               # Alert email notification module
├── docker_compose.yml              # Docker Compose orchestration for all services
├── ids_system.log                  # IDS runtime output log
├── ids_system_error.log            # IDS error log
├── ids_system_live.log             # Live monitoring output log
├── 
└── README.md                       # This file
```

---

## System Architecture

The detection pipeline processes network traffic through four sequential layers:

```
Smart Grid Traffic (Modbus / DNP3 / IEC 61850)
        │
        ▼
┌─────────────────────────────────────────────────┐
│  Layer 1 — Data Collection                      │
│  Zeek: protocol metadata extraction             │
│  Suricata: packet capture & deep inspection     │
└───────────────────┬─────────────────────────────┘
                    │
        ┌───────────┴────────────┐
        ▼                        ▼
┌──────────────────┐   ┌─────────────────────────┐
│  Layer 2a        │   │  Layer 2b               │
│  Signature IDS   │   │  Anomaly Detection      │
│  (Suricata)      │   │  (Isolation Forest)     │
│  Known threats   │   │  Unknown / zero-day     │
└──────────────────┘   └──────────┬──────────────┘
                                  │ Suspicious?
                                  ▼
                       ┌─────────────────────────┐
                       │  Layer 3 — Sandbox      │
                       │  Docker (local) +       │
                       │  VirusTotal API (cloud) │
                       └──────────┬──────────────┘
                                  │
                                  ▼
                       ┌─────────────────────────┐
                       │  ELK Stack              │
                       │  Elasticsearch /        │
                       │  Logstash / Kibana      │
                       │  Email engine/Dashboard │
                       └─────────────────────────┘
```

---

## Prerequisites

| Requirement | Version | Purpose |
|---|---|---|
| Ubuntu | 22.04 LTS | Host operating system |
| Python | 3.10 | Core framework language |
| Docker | 4.69.0 | Sandbox containerisation and service orchestration |
| Suricata | 7.0 | Signature-based IDS engine |
| Zeek | 8.12 | Network metadata extraction |
| Elasticsearch | 9.4.0 | Log storage and indexing |
| Logstash | 8.11 | Log ingestion pipeline |
| Kibana | 9.3.3 | Real-time dashboard and visualisation |

### Python Dependencies

```bash
pip install pandas scikit-learn joblib requests
```

---

## Environment Variables

Set the following variables before running (add to `.env` or export in your shell):

| Variable | Description | Default |
|---|---|---|
| `VIRUSTOTAL_API_KEY` | VirusTotal v3 API key | *(required for cloud sandbox)* |
| `HYBRID_ANALYSIS_API_KEY` | Hybrid Analysis API key | *(optional)* |
| `SANDBOX_SERVICE` | Which cloud sandbox to use: `virustotal`, `hybrid_analysis`, or `local_only` | `virustotal` |

---

## Installation and Setup

### 1. Clone the Repository

```bash
git clone https://github.com/Daniii-elle/Hybrid-Sandboxed-IDS-for-Zero-Day-Threats-in-Smart-Grids.git
cd Hybrid-Sandboxed-IDS-for-Zero-Day-Threats-in-Smart-Grids
```

### 2. Start All Services with Docker Compose

```bash
docker-compose up -d
```

This starts Elasticsearch (port 9201), Logstash, and Kibana (port 5601).

### 3. Build the Sandbox Container

```bash
docker build -t sandbox_env ./sandbox/
```

### 4. Initialise ELK Indices

```bash
python setup_elk.py
```

### 5. Prepare the Dataset

Download the UNSW-NB15 training CSV and place it at:

```
data/raw/unsw_train.csv
```

UNSW-NB15 is available from the UNSW Canberra Cyber Security Lab:
https://research.unsw.edu.au/projects/unsw-nb15-dataset

### 6. Train the Anomaly Detection Model

The model trains automatically on first run. To train manually:

```python
# From ids_full_system.py
python -c "from ids_full_system import train_model; train_model()"
```

This saves `model.pkl` to the project root.

---

## Running the System

### Terminal 1 — Start the IDS Pipeline

```bash
python ids_full_system.py
```

Expected output:
```
Initializing ELK indices...
ELK system ready
Training Isolation Forest... (first run only)
Model trained and saved as model.pkl.
Waiting for Zeek logs...
```

### Terminal 2 — Run the Attack Simulation

```bash
python test_attack_generator.py
```

This injects 10 attack scenarios into `logs/conn.log` at 5-second intervals, simulating:

| # | Attack Name | Severity | Protocol |
|---|---|---|---|
| 1 | DDoS Flood | CRITICAL | Modbus/TCP (port 502) |
| 2 | Data Exfiltration | CRITICAL | HTTPS (port 443) |
| 3 | SCADA Command Injection | CRITICAL | Modbus/TCP (port 502) |
| 4 | IEC 61850 Protocol Abuse | HIGH | IEC 61850 (port 102) |
| 5 | SSH Brute Force | HIGH | SSH (port 22) |
| 6 | DNS Tunnelling | HIGH | DNS/UDP (port 53) |
| 7 | Port Scan Reconnaissance | MEDIUM | TCP (random port) |
| 8 | Ransomware C2 Beacon | CRITICAL | HTTPS (port 443) |
| 9 | Man-in-the-Middle (ARP Spoof) | CRITICAL | HTTP (port 80) |
| 10 | Zero-Day Exploit Attempt | CRITICAL | IEC 61850 (port 102) |

### View Kibana Dashboard

Open your browser at: **http://localhost:5601**

### Email and Flask Dashboard Report

1. Install Flask
python -m pip install -r requirements.txt

2. Interactive setup (recommended)
python setup_dashboard.py

3. Start everything
python run_ids_with_dashboard.py

4. Open browser
http://localhost:5000


### What Non-Technical Stakeholders Get
Email Reports (every 30 minutes). 
Plain-English threat summary. 
Counts of anomalies/alerts/suspicious files. 
Direct link to dashboard(Refresh rate of 30 secs). 
Recommended actions

### Email Setup
Gmail (most common):
Go to: https://myaccount.google.com/apppasswords 
Generate an App Password
Set as SMTP_PASSWORD

```Windows PowerShell:
$env:SMTP_USER = 'you@gmail.com'
$env:SMTP_PASSWORD = 'xxxx xxxx xxxx xxxx'
$env:REPORT_TO = 'recipient@example.com'
$env:DASHBOARD_URL = 'http://localhost:5000'
$env:IDS_DASHBOARD_PORT = '5000'
```
### OR
Edit all values in .env file. Use .env.example as a guide

---
## Detection Pipeline — What to Expect

When the attack generator runs, Terminal 1 will show output like:

```
Anomaly Detected! (3 found)
Running local Docker sandbox...
Suspicious behavior detected — potential malware
Escalating to cloud sandbox...
VirusTotal: 0 detections (CSV files are not malware — expected)
Saved cloud API result to results/anomaly_12_cloud.json
```

Sandbox analysis results are saved to the `results/` directory as JSON files.

---

## Evaluation Metrics

The framework is evaluated using the following classification metrics:

| Metric | Formula | Target |
|---|---|---|
| Detection Rate (Recall) | TP / (TP + FN) | ≥ 0.90 (known), ≥ 0.75 (zero-day) |
| False Positive Rate | FP / (FP + TN) | ≤ 0.10 |
| Precision | TP / (TP + FP) | — |
| F1-Score | 2TP / (2TP + FP + FN) | — |
| Accuracy | (TP + TN) / Total | — |
| Alert Response Time | ms from detection to alert | ≤ 500ms (Sig/Anomaly), ≤ 2000ms (Sandbox) |

Statistical significance of the hybrid vs. Suricata-only baseline is assessed using **McNemar's test** (χ² with 1 degree of freedom, α = 0.05).

---

## Source File Summary (Appendix Reference)

| Appendix | File(s) | Description |
|---|---|---|
| A.1 | `ids_full_system.py` | Main IDS pipeline: model training, Zeek parsing, monitoring loop, sandbox integration, ELK logging |
| A.2 | `elk_api.py` | ELK Stack API client: index management, document indexing, anomaly/alert search |
| A.3 | `sandbox/virustotal_api.py` | Sandbox escalation: VirusTotal v3 API and Hybrid Analysis API integration |
| A.4 | `sandbox/runner.py` | Docker sandbox execution runner and behavioural monitoring |
| A.5 | `test_attack_generator.py` | Live attack simulation: 10 smart grid attack scenarios injected into Zeek conn.log |
| A.6 | `log_generator.py` | Synthetic normal Modbus/DNP3 traffic generator for model baseline training |
| A.7 | `setup_elk.py` | ELK index initialisation and health check utility |
| A.8 | `setup_sandbox.py` | Docker sandbox build verification and environment check |
| A.9 | `email_reporter.py` | Alert email notification module |
| A.10 | `docker_compose.yml` | Docker Compose service definitions (ELK Stack + sandbox) |
| A.11 | `suricata-config/` | Suricata configuration: `suricata.yaml`, `classification.config`, `threshold.config`, `update.yaml` |

---

## Key Technologies and References

- **Suricata 7.0** — Open Information Security Foundation (OISF, 2023). https://docs.suricata.io/en/suricata-7.0.11/
- **Zeek** — Paxson, V. (1999). Bro: A system for detecting network intruders in real-time. *Computer Networks*, 31(23–24), 2435–2463.
- **Isolation Forest** — Liu, F. T., Ting, K. M., & Zhou, Z.-H. (2008). Isolation Forest. *Proceedings of ICDM 2008*, 413–422. https://doi.org/10.1109/ICDM.2008.17
- **UNSW-NB15 Dataset** — Moustafa, N., & Slay, J. (2015). UNSW-NB15: A comprehensive data set for network intrusion detection systems. *MilCIS 2015*. https://research.unsw.edu.au/projects/unsw-nb15-dataset
- **ELK Stack** — Elastic N.V. (2023). Elasticsearch 8.11 Documentation. https://www.elastic.co/guide/en/elasticsearch/reference/8.11/
- **VirusTotal API** — VirusTotal (2023). VirusTotal API v3 Documentation. https://developers.virustotal.com/reference/overview
- **Docker** — Docker Inc. (2023). Docker Engine Documentation. https://docs.docker.com/engine/
- **AegisGuard (related work)** — Abou, E. M. M., Sayed, S. G., & El-Dakroury, M. M. (2025). AegisGuard: A Multi-Stage Hybrid IDS for Industrial IoT. *Sensors*. https://pmc.ncbi.nlm.nih.gov/articles/PMC12655908/
- **ICS-SimLab (related work)** — Brown, J., et al. (2025). ICS-SimLab: A Containerized Approach for Simulating ICS for Cyber Security Research. https://doi.org/10.36227/techrxiv

---

## Ethical Statement

All attack simulations are conducted exclusively within the isolated Docker/VM laboratory environment. No experiments are conducted against production systems, real grid infrastructure, or any third-party networks. Malware samples are sourced from legitimate research repositories (UNSW-NB15) and securely deleted after testing. This research follows the ACM Code of Ethics, the IEEE Code of Ethics, and the academic integrity policies of Miva Open University.

---

## Acknowledgements

Supervised by **Prof. Wilson Nwankwo**, Department of Cyber Security, Miva Open University. Dedicated to God Almighty and to Barr. Jayne Abuo, whose support and guidance made this journey possible.

---

## Licence

This project is developed for academic research purposes only and submitted in partial fulfilment of the requirements for the award of a Bachelor of Science (Honours) in Cyber Security, Miva Open University, April 2026.
