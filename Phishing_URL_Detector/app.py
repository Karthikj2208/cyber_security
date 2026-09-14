from flask import Flask, render_template, request, jsonify
from utils.feature_extractor import extract_features, FEATURE_NAMES
from model.predictor import PhishingPredictor

app = Flask(__name__)
predictor = PhishingPredictor()

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/analyze", methods=["POST"])
def analyze():
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "Please enter a URL."}), 400

    features = extract_features(url)
    result = predictor.predict(url, features)
    return jsonify({
        "url": url,
        "prediction": result["prediction"],
        "risk_score": result["risk_score"],
        "confidence": result["confidence"],
        "features": features,
        "feature_names": FEATURE_NAMES,
        "explanation": result["explanation"]
    })

if __name__ == "__main__":
    app.run(debug=True)
