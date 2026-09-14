import json
import random
import threading
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

LOG_FILE = Path("logs/intrusion_alerts.jsonl")

class IntrusionDetector:
    """
    Lightweight educational IDS.
    It analyzes packet-like records and raises alerts from transparent rules.
    It does not capture traffic automatically; demo traffic is synthetic.
    """

    RULES = [
        ("PORT_SCAN", lambda p: p["dst_port"] in range(1, 1025) and p["packet_count"] >= 12),
        ("BRUTE_FORCE", lambda p: p["dst_port"] in (21, 22, 23, 25, 3389) and p["connection_count"] >= 8),
        ("SYN_FLOOD", lambda p: p["protocol"] == "TCP" and p["flags"] == "SYN" and p["packet_count"] >= 80),
        ("SUSPICIOUS_DNS", lambda p: p["protocol"] == "DNS" and p["query_length"] >= 80),
        ("HIGH_RATE", lambda p: p["packet_count"] >= 120),
    ]

    def __init__(self):
        self.lock = threading.Lock()
        self.alerts = []
        self.stats = Counter()
        self.started_at = time.time()
        LOG_FILE.parent.mkdir(exist_ok=True)
        self._load_logs()

    def _load_logs(self):
        if not LOG_FILE.exists():
            return
        try:
            for line in LOG_FILE.read_text(encoding="utf-8").splitlines()[-500:]:
                self.alerts.append(json.loads(line))
        except Exception:
            self.alerts = []

    def analyze_packet(self, packet):
        matched = []
        for name, rule in self.RULES:
            try:
                if rule(packet):
                    matched.append(name)
            except (KeyError, TypeError):
                pass

        severity = "INFO"
        if len(matched) >= 2 or "SYN_FLOOD" in matched:
            severity = "CRITICAL"
        elif matched:
            severity = "HIGH"

        self.stats["packets"] += 1
        self.stats["alerts"] += bool(matched)

        if not matched:
            return None

        alert = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "severity": severity,
            "type": ", ".join(matched),
            "source_ip": packet.get("src_ip", "unknown"),
            "destination_ip": packet.get("dst_ip", "unknown"),
            "destination_port": packet.get("dst_port", "-"),
            "protocol": packet.get("protocol", "-"),
            "packet_count": packet.get("packet_count", 0),
            "message": self._message(matched, packet),
        }
        with self.lock:
            self.alerts.append(alert)
            self.alerts = self.alerts[-500:]
            with LOG_FILE.open("a", encoding="utf-8") as f:
                f.write(json.dumps(alert) + "\n")
        return alert

    def _message(self, matched, p):
        parts = []
        if "PORT_SCAN" in matched:
            parts.append("Possible port scanning activity")
        if "BRUTE_FORCE" in matched:
            parts.append("Possible repeated authentication attempts")
        if "SYN_FLOOD" in matched:
            parts.append("Possible TCP SYN flood")
        if "SUSPICIOUS_DNS" in matched:
            parts.append("Unusually long DNS query")
        if "HIGH_RATE" in matched:
            parts.append("Abnormally high packet rate")
        return "; ".join(parts)

    def generate_demo_traffic(self, count=20):
        normal = [
            {"src_ip":"10.0.0.12","dst_ip":"10.0.0.1","dst_port":443,"protocol":"TCP","flags":"ACK","packet_count":4,"connection_count":1,"query_length":20},
            {"src_ip":"10.0.0.15","dst_ip":"8.8.8.8","dst_port":53,"protocol":"DNS","flags":"","packet_count":2,"connection_count":1,"query_length":28},
            {"src_ip":"10.0.0.20","dst_ip":"10.0.0.5","dst_port":80,"protocol":"TCP","flags":"ACK","packet_count":6,"connection_count":2,"query_length":0},
        ]
        suspicious = [
            {"src_ip":"192.168.1.77","dst_ip":"10.0.0.10","dst_port":22,"protocol":"TCP","flags":"SYN","packet_count":16,"connection_count":12,"query_length":0},
            {"src_ip":"203.0.113.50","dst_ip":"10.0.0.20","dst_port":80,"protocol":"TCP","flags":"SYN","packet_count":140,"connection_count":30,"query_length":0},
            {"src_ip":"198.51.100.23","dst_ip":"10.0.0.53","dst_port":53,"protocol":"DNS","flags":"","packet_count":3,"connection_count":1,"query_length":110},
        ]
        for i in range(count):
            p = random.choice(suspicious if i % 5 == 0 else normal)
            self.analyze_packet(p)

    def get_logs(self, limit=100):
        with self.lock:
            return list(reversed(self.alerts[-limit:]))

    def status(self):
        with self.lock:
            by_severity = Counter(a["severity"] for a in self.alerts)
            by_type = Counter()
            for a in self.alerts:
                for t in a["type"].split(", "):
                    by_type[t] += 1
            return {
                "packets_analyzed": self.stats["packets"],
                "alerts": len(self.alerts),
                "critical": by_severity["CRITICAL"],
                "high": by_severity["HIGH"],
                "info": by_severity["INFO"],
                "top_alert": by_type.most_common(1)[0][0] if by_type else "None",
                "uptime_seconds": int(time.time() - self.started_at),
            }
