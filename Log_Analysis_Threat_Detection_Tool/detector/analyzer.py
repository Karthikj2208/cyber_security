import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

FAILED_RE = re.compile(
    r"(?P<ts>[A-Z][a-z]{2}\s+\d+\s+\d\d:\d\d:\d\d).*?"
    r"(?:Failed password|authentication failure|Invalid user).*?"
    r"(?:from\s+)?(?P<ip>(?:\d{1,3}\.){3}\d{1,3})"
)

GENERIC_IP_RE = re.compile(r"(?:from|rhost=|src=)(?P<ip>(?:\d{1,3}\.){3}\d{1,3})")

class LogAnalyzer:
    def __init__(self, alert_path):
        self.alert_path = Path(alert_path)
        self.alert_path.parent.mkdir(parents=True, exist_ok=True)
        self.last_result = {
            "lines": 0, "failed_logins": 0, "unique_ips": 0,
            "suspicious_ips": 0, "bruteforce_events": 0,
            "alerts": []
        }

    def analyze_file(self, path):
        text = Path(path).read_text(encoding="utf-8", errors="replace")
        lines = text.splitlines()
        failures = []
        all_ips = Counter()
        ip_failures = Counter()

        for line in lines:
            for m in GENERIC_IP_RE.finditer(line):
                all_ips[m.group("ip")] += 1
            m = FAILED_RE.search(line)
            if m:
                ip = m.group("ip")
                failures.append({"line": line, "ip": ip, "timestamp": m.group("ts")})
                ip_failures[ip] += 1

        alerts = []
        # Threshold is intentionally transparent and configurable for lab use.
        for ip, count in ip_failures.items():
            if count >= 5:
                severity = "CRITICAL" if count >= 15 else "HIGH"
                alerts.append({
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "severity": severity,
                    "type": "BRUTE_FORCE",
                    "source_ip": ip,
                    "count": count,
                    "message": f"{count} failed login attempts observed from {ip}."
                })
            elif count >= 3:
                alerts.append({
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "severity": "MEDIUM",
                    "type": "REPEATED_FAILURES",
                    "source_ip": ip,
                    "count": count,
                    "message": f"Repeated authentication failures observed from {ip}."
                })

        # Suspicious IP activity: high event volume from one source.
        for ip, count in all_ips.items():
            if count >= 20 and ip not in ip_failures:
                alerts.append({
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "severity": "MEDIUM",
                    "type": "SUSPICIOUS_IP_ACTIVITY",
                    "source_ip": ip,
                    "count": count,
                    "message": f"High log-event volume observed for source IP {ip}."
                })

        for alert in alerts:
            with self.alert_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(alert) + "\n")

        self.last_result = {
            "lines": len(lines),
            "failed_logins": len(failures),
            "unique_ips": len(all_ips),
            "suspicious_ips": sum(1 for a in alerts if a["type"] == "SUSPICIOUS_IP_ACTIVITY"),
            "bruteforce_events": sum(1 for a in alerts if a["type"] == "BRUTE_FORCE"),
            "alerts": alerts,
            "top_failed_ips": ip_failures.most_common(10)
        }
        return self.last_result

    def get_alerts(self):
        if not self.alert_path.exists():
            return []
        rows = []
        for line in self.alert_path.read_text(encoding="utf-8").splitlines()[-200:]:
            try: rows.append(json.loads(line))
            except json.JSONDecodeError: pass
        return list(reversed(rows))

    def status(self):
        alerts = self.get_alerts()
        c = Counter(a["severity"] for a in alerts)
        return {
            "lines": self.last_result["lines"],
            "failed_logins": self.last_result["failed_logins"],
            "unique_ips": self.last_result["unique_ips"],
            "alerts": len(alerts),
            "critical": c["CRITICAL"],
            "high": c["HIGH"],
            "medium": c["MEDIUM"],
            "bruteforce_events": self.last_result["bruteforce_events"]
        }
