# Network Traffic Analyzer

A real‑time (or offline) network traffic analyzer built with **Streamlit** for the dashboard, **PyShark/Scapy** for capture/parsing, and **scikit‑learn** for protocol classification and anomaly detection.

## Key Capabilities
- Live capture via **PyShark** (TShark/Wireshark backend) or offline **PCAP upload**.
- Feature extraction per packet (size, IAT, IP/port stats, TCP flags, protocol hints).
- **Protocol classification** (HTTP/HTTPS/DNS/FTP/SMTP/TCP/UDP/Other) using RandomForest.
- **Anomaly detection** using IsolationForest with tunable threshold.
- Streamlit dashboard with metrics, protocol distribution, time series, and alerts.
- Works in three modes: **Live**, **PCAP Upload**, **CSV Upload** (for demos without capture privileges).

> Tip: If you cannot install TShark or don't have root/admin capture privileges, use *PCAP Upload* or *CSV Upload* modes to try the app immediately.

## Quickstart

### 0) Prerequisites
- Python 3.9+ (3.11 recommended)
- **TShark** (from Wireshark) installed and on PATH for PyShark live capture. On Ubuntu: `sudo apt install tshark` (grant capture permissions or run with sudo). On Windows, install Wireshark (includes TShark).

### 1) Create & activate a virtual environment
```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS/Linux
source .venv/bin/activate
```

### 2) Install dependencies
```bash
pip install -r app/requirements.txt
```

### 3) Run the Streamlit app
```bash
streamlit run app/streamlit_app.py
```
### 4) Try it
- **Live Capture**: Select an interface and click **Start** (requires TShark & privileges).
- **PCAP Upload**: Upload a `.pcap` or `.pcapng` file.
- **CSV Upload**: Upload a CSV that matches `data/schema.csv` (header only in repo).

## How it Works 
1. **Capture/Load**: We use PyShark (TShark) for live capture or PCAP parsing. As a fallback, CSV uploads simulate traffic for demo and benchmarking.
2. **Feature Extraction**: `features.py` computes per‑packet features (length, IAT, protocol number, TCP flags, IP/port bins, flow stats).
3. **Classification**: `model.py` maps PyShark `highest_layer` into coarse protocol classes and trains/evaluates a RandomForest when labels exist (PCAP path) or loads a saved model.
4. **Anomaly Detection**: `anomaly.py` fits an IsolationForest and flags outliers with an adjustable threshold.
5. **Visualization**: `streamlit_app.py` shows protocol distributions, time‑series rates, top talkers, confusion matrix, ROC (when applicable), and anomaly alerts.
