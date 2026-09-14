import os
import joblib
from utils.feature_extractor import extract_feature_vector

MODEL_PATH = os.path.join(os.path.dirname(__file__), "phishing_model.joblib")

class PhishingPredictor:
    def __init__(self):
        self.bundle = joblib.load(MODEL_PATH) if os.path.exists(MODEL_PATH) else None

    def predict(self, url, features):
        if self.bundle is None:
            # Deterministic fallback until train_model.py is run.
            score = self.heuristic_score(url, features)
            prediction = "Phishing" if score >= 50 else "Likely Legitimate"
            confidence = abs(score - 50) * 2
            return {
                "prediction": prediction,
                "risk_score": round(score, 1),
                "confidence": round(min(confidence, 99.0), 1),
                "explanation": self.explanation(features, score)
            }

        model = self.bundle["model"]
        vector = [extract_feature_vector(url)]
        probabilities = model.predict_proba(vector)[0]
        phishing_index = list(model.classes_).index(1)
        phishing_prob = float(probabilities[phishing_index])
        score = phishing_prob * 100
        prediction = "Phishing" if phishing_prob >= 0.5 else "Likely Legitimate"

        return {
            "prediction": prediction,
            "risk_score": round(score, 1),
            "confidence": round(max(probabilities) * 100, 1),
            "explanation": self.explanation(features, score)
        }

    @staticmethod
    def heuristic_score(url, f):
        score = 8
        score += min(f["url_length"] / 5, 18)
        score += min(f["subdomain_count"] * 7, 21)
        score += f["has_ip"] * 24
        score += f["has_punycode"] * 22
        score += min(f["suspicious_word_count"] * 7, 28)
        score += min(f["at_count"] * 18, 18)
        score += min(f["hyphen_count"] * 1.5, 10)
        score += f["has_port"] * 6
        score -= f["has_https"] * 5
        return max(0, min(score, 100))

    @staticmethod
    def explanation(f, score):
        reasons = []
        if f["has_ip"]: reasons.append("Uses an IP address instead of a normal hostname")
        if f["has_punycode"]: reasons.append("Contains punycode in the hostname")
        if f["suspicious_word_count"]: reasons.append("Contains security/account-related keywords")
        if f["at_count"]: reasons.append("Contains '@', which can obscure the real destination")
        if f["subdomain_count"] >= 2: reasons.append("Uses multiple subdomain levels")
        if f["url_length"] > 100: reasons.append("Unusually long URL")
        if not reasons: reasons.append("No strong lexical warning signs were detected")
        return reasons[:5]
