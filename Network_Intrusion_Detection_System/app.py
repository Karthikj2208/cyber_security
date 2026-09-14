from flask import Flask, render_template, jsonify, request
from detector import IntrusionDetector

app = Flask(__name__)
detector = IntrusionDetector()

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/status")
def status():
    return jsonify(detector.status())

@app.route("/api/logs")
def logs():
    limit = min(int(request.args.get("limit", 100)), 500)
    return jsonify(detector.get_logs(limit))

@app.route("/api/scan-demo", methods=["POST"])
def scan_demo():
    """Generate safe synthetic traffic for demonstration/testing."""
    count = min(max(int((request.get_json(silent=True) or {}).get("count", 20)), 1), 100)
    detector.generate_demo_traffic(count)
    return jsonify(detector.status())

if __name__ == "__main__":
    app.run(debug=True)
