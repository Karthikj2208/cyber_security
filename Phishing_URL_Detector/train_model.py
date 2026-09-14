import os
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, classification_report
from utils.feature_extractor import extract_feature_vector, FEATURE_NAMES

DATA_PATH = "data/sample_urls.csv"
MODEL_PATH = "model/phishing_model.joblib"

df = pd.read_csv(DATA_PATH)
X = df["url"].apply(extract_feature_vector).tolist()
y = df["label"].astype(int)

model = Pipeline([
    ("scaler", StandardScaler()),
    ("classifier", RandomForestClassifier(
        n_estimators=250,
        max_depth=8,
        random_state=42,
        class_weight="balanced"
    ))
])

model.fit(X, y)
pred = model.predict(X)
print(f"Training accuracy on demo dataset: {accuracy_score(y, pred):.2%}")
print(classification_report(y, pred, target_names=["Legitimate", "Phishing"], zero_division=0))

os.makedirs("model", exist_ok=True)
joblib.dump({
    "model": model,
    "feature_names": FEATURE_NAMES
}, MODEL_PATH)
print(f"Saved model to {MODEL_PATH}")
