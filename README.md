# VerifAI-v2 — Explainable Malicious-URL Triage (SOC Analyst Build)

Rebuilt for learning + hiring in Tokyo / Singapore. Original thesis project
(`Goodpeace/VerifAI`, 24k URLs, 21 features, XGBoost 98.5%) is preserved untouched.
This is the clean, explainable, deployable version you can defend in interviews.

## What it does
Paste a URL → lexical analysis (no visit, safe) → Random Forest verdict
(Malicious/Legitimate + confidence) → plain-English reasons → SQLite audit trail.

## Run in 3 commands
```bash
pip install -r requirements.txt
python train_model.py
python app.py
# open http://127.0.0.1:5000
```

## Structure (read in this order)
```
config.py            constants
feature_extractor.py URL -> 10 numbers  ← study this first
train_model.py       CSV -> models/*.joblib
explainer.py         numbers -> English
database.py          audit trail
app.py               Flask: /predict, /history
data/sample_urls.csv 20 labelled URLs to learn on
tests/               3 smoke tests
docs/00-start-here.md  10-min concept guide
```

## Skills this proves (for resumes)
Phishing triage logic · Feature engineering · sklearn (LR/RF, train/test split,
confusion matrix, false-positive awareness) · Flask REST API · SQLite audit logging ·
Tests · Git hygiene. Next: Docker + deploy + XGBoost + WHOIS (see docs/).

## From v2 back to your 24k thesis
Replace `data/sample_urls.csv` with your `urls_labelled.csv`, retrain —
pipeline is identical, metrics jump to thesis numbers.

## Safety
Target URL is never fetched. Only the string is analysed.
