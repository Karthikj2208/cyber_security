# Python Port Scanner

Basic cybersecurity project using Python sockets.

## Features
- TCP port detection
- Hostname/IP resolution
- Common service identification
- Custom port range
- CSV and TXT report export
- No external Python packages

## Run in VS Code
Open this folder in VS Code and run:

```powershell
python main.py
```

Or:

```powershell
py main.py
```

Example safe target for learning:

```text
127.0.0.1
```

Try ports `1` to `100` first.

## Example output

```text
[OPEN]    22  SSH
[OPEN]    80  HTTP

Scan completed.
CSV report: results/scan_YYYYMMDD_HHMMSS.csv
TXT report: results/scan_YYYYMMDD_HHMMSS.txt
```

## Project structure

```text
Port_Scanner/
├── main.py
├── README.md
├── requirements.txt
├── results/
└── screenshots/
```

## Cybersecurity concepts
- TCP three-way connection concept
- Port numbers
- Services and protocols
- Sockets
- Network reconnaissance
- Security reporting

## Safety
Only scan `localhost`, your own devices, or systems for which you have explicit authorization. Keep the scan range small for the basic project.

## Viva questions
1. What is a port?
2. What is TCP?
3. What is a socket?
4. What does an open port mean?
5. What is the difference between TCP and UDP?
6. Why are ports associated with services?
7. Why should scanning be authorized?
8. How does `connect_ex()` help detect an open TCP port?
