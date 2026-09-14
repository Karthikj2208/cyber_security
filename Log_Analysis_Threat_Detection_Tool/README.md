# Log Analysis & Threat Detection Tool

Python + Linux-log analysis project for detecting repeated failed logins, suspicious IP activity and brute-force indicators, then generating automated JSON alerts and a Flask dashboard.

## Features
- Linux-style authentication log parsing
- Failed-login detection
- Per-IP failure counting
- Brute-force thresholds
- Suspicious IP volume detection
- Severity levels: Medium / High / Critical
- Automated JSONL alert generation
- Web dashboard
- Sample `auth.log` for safe testing

## Run in VS Code

```powershell
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Open:
`http://127.0.0.1:5000`

Enter the default:
`sample_logs/auth.log`

Click **Analyze Log**.

## Linux usage

On an authorized Linux system, copy or point the analyzer at an appropriate authentication log, commonly:
- `/var/log/auth.log` on Debian/Ubuntu
- `/var/log/secure` on some RHEL/CentOS systems

You may need appropriate permissions to read system logs.

## Detection logic
- 3+ failures from an IP → repeated-failure alert
- 5+ failures from an IP → brute-force alert
- 15+ failures from an IP → critical brute-force alert
- 20+ generic IP events without being a failed-login source → suspicious IP activity

These are simple educational thresholds, not a replacement for SIEM/EDR detection.

## Resume description
**Log Analysis & Threat Detection Tool — Python, Linux Logs:** Built a security log analyzer that parses Linux authentication logs, aggregates failed login attempts by source IP, detects brute-force indicators and suspicious IP activity, generates severity-based automated alerts, and visualizes threat events through a Flask dashboard.
