# Phishing URL Detector

A beginner-friendly cybersecurity project built with **Python + Flask**. It extracts URL features, applies a machine-learning classifier, calculates a 0–100 risk score, and displays the result in a dashboard.

## Features
- URL feature extraction
- Machine-learning classification using Random Forest
- 0–100 phishing risk score
- Explainable feature indicators
- Flask REST API
- Responsive dashboard
- Demo training dataset included

## Project structure
```text
Phishing_URL_Detector/
├── app.py
├── requirements.txt
├── train_model.py
├── README.md
├── data/
│   └── sample_urls.csv
├── model/
│   └── (generated phishing_model.joblib)
├── utils/
│   ├── __init__.py
│   └── feature_extractor.py
├── model/
│   ├── __init__.py
│   └── predictor.py
├── templates/
│   └── index.html
└── static/
    ├── style.css
    └── app.js
```

## Run in VS Code

Open the project folder in VS Code terminal.

### Windows
```powershell
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python train_model.py
python app.py
```

Then open:
`http://127.0.0.1:5000`

If `python` is not recognized, try:
```powershell
py -m venv venv
py -m pip install -r requirements.txt
py train_model.py
py app.py
```

## Important note
This is an **educational detector**, not a production-grade URL reputation service. The included dataset is intentionally small so the project runs offline. For real-world accuracy, train on a large, current, labelled dataset and combine this model with reputation feeds, DNS/TLS checks, sandboxing, and other security controls.

## API example
POST `/api/analyze`
```json
{
  "url": "https://example.com"
}
```

The response contains the prediction, risk score, confidence, extracted features, and explanation.

## Suggested resume description
**Phishing URL Detector — Python, Flask, Scikit-learn:** Built a web-based phishing URL detection system that extracts lexical and structural URL features, classifies suspicious URLs using a Random Forest model, and visualizes a 0–100 risk score with explainable indicators through a Flask dashboard.
