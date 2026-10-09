# VerifAI-v2 — Explainable Malicious-URL Triage (SOC Analyst Build)

**Live demo: https://verifai-v2.onrender.com** (free tier sleeps ~30s on first load)

Rebuilt for learning + hiring in Tokyo / Singapore. Original thesis project
(`Goodpeace/VerifAI`, 24k URLs, 21 features, XGBoost 98.5%) is preserved untouched.
This is the clean, explainable, deployable version you can defend in interviews.

## What it does
Paste a URL → Tier-1 lexical RF (<1ms, verdict Malicious/Uncertain/Legitimate)
→ Tier-2 host intel (WHOIS age + DNS) resolves Uncertain only
→ exact model-faithful English reasons → SQLite audit trail.

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
train_model.py       CSV -> models/*.joblib (+ host-only augmentation)
tune_threshold.py    out-of-fold threshold for ~0.5% FPR (test untouched)
explainer.py         exact tree contributions -> English (zero new deps)
host_intel.py        Tier-2 WHOIS/DNS, 4s bound, cache, never raises
database.py          audit trail
app.py               Flask: /predict (30/min), /history, /health
data/sample_urls.csv 20 labelled URLs to learn on
data/urls_labelled.csv 24,096 thesis URLs (50/50, pre-split)
tests/               12 tests (features, exactness, bands, host logic)
docs/                00-start-here, 01-scale-to-24k, 02-standard-explanations,
                     03-host-signals, MODEL_CARD
```

## Skills this proves (for resumes)
Phishing triage logic · Feature engineering + train augmentation ·
sklearn (RF, OOF threshold tuning, confusion matrix, FPR-aware operating
points) · Exact model-faithful XAI without new deps · Two-tier
lexical+host architecture with latency budgets · Flask REST API + rate
limiting · SQLite audit logging · Docker + Render deploy · CI + model card.

## Full-scale results (24k URLs, lexical-only 10 features)
Operating point thr=0.95 (tuned out-of-fold for ~0.5% FPR, test untouched).
Unseen test (3,615 URLs): RF **95.19%** acc, **99.82%** prec, 90.54% rec,
**0.17% FPR (3 FP)** · review band 3.8% Uncertain for manual triage.
Explanations are exact tree-path contributions (proof in
`docs/02-standard-explanations.md`), not heuristics.

## Safety
Target URL is never fetched. Only the string is analysed.
