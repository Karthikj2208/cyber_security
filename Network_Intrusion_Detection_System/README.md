# Network Intrusion Detection System (NIDS)

A Python-based educational Network Intrusion Detection System that analyzes packet-like network records, detects suspicious traffic with transparent rules, generates alerts, stores JSONL logs, and displays a Flask dashboard.

## Features
- Packet/traffic analysis
- Port scan detection
- Brute-force pattern detection
- TCP SYN flood detection
- Suspicious DNS query detection
- High packet-rate detection
- Severity classification
- JSONL alert logging
- Flask dashboard
- Safe synthetic traffic generator for demonstrations

## Run in VS Code

```powershell
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Open:
`http://127.0.0.1:5000`

Click **Generate Demo Traffic** to populate the dashboard.

## Important
This project intentionally uses **synthetic packet records** instead of automatically sniffing a live network. That makes it safe and easy to run on a student laptop without requiring administrator/root packet-capture privileges.

For a production-grade NIDS, replace the synthetic input with an authorized packet-capture source (for example, Scapy/libpcap), add flow aggregation, a larger rule/signature set, anomaly detection, allowlists, alert deduplication, and persistent storage.

## Resume description
**Network Intrusion Detection System — Python, Flask:** Developed an educational NIDS that analyzes network traffic patterns, detects port scans, brute-force behavior, SYN floods, suspicious DNS queries and high-rate traffic, generates severity-based alerts, and visualizes security events through a Flask dashboard with JSONL logging.
