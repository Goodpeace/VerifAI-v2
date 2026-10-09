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
Operating point thr=0.95 (tuned out-of-fold for ~0.5% FPR, test untouched).
Unseen test (3,615 URLs): RF **95.19%** acc, **99.82%** prec, 90.54% rec,
**0.17% FPR (3 FP)** · review band 3.8% Uncertain for manual triage.
Explanations are exact tree-path contributions (proof in
`docs/02-standard-explanations.md`), not heuristics.

## Safety
Target URL is never fetched. Only the string is analysed.
