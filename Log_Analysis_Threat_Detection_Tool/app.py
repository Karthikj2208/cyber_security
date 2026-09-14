from flask import Flask, render_template, jsonify, request
from detector.analyzer import LogAnalyzer
from pathlib import Path

app = Flask(__name__)
analyzer = LogAnalyzer("logs/threat_alerts.jsonl")

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/analyze", methods=["POST"])
def analyze():
    data = request.get_json(silent=True) or {}
    path = data.get("path", "sample_logs/auth.log")
    if not Path(path).exists():
        return jsonify({"error": f"Log file not found: {path}"}), 404
    result = analyzer.analyze_file(path)
    return jsonify(result)

@app.route("/api/status")
def status():
    return jsonify(analyzer.status())

@app.route("/api/alerts")
def alerts():
    return jsonify(analyzer.get_alerts())

if __name__ == "__main__":
    app.run(debug=True)
