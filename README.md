# VerifAI-v2 — Explainable Malicious-URL Triage (SOC Analyst Build)

**Live demo: https://verifai-v2.onrender.com** (free tier sleeps ~30s on first load)

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

## Full-scale results (24k URLs, lexical-only 10 features)
`python train_model.py --full` → test set (3,615 URLs):
RF **97.51%** acc, 98.92% prec, 96.07% rec, **1.05% FPR** ·
LR 93.53% acc. Thesis (21 feat + WHOIS): RF 97.68%, XGB 98.56%.
Full table + interview lines: `docs/01-scale-to-24k.md`.

## Safety
Target URL is never fetched. Only the string is analysed.
