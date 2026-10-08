# Stage 6: 24k scale-up — what just happened

## Command
```bash
python train_model.py --full
```

## Results (test set, 3,615 URLs — lexical-only, 10 features)
| Model | Acc | Prec | Rec | F1 | FPR |
|---|---|---|---|---|---|
| Logistic Regression | 0.9353 | 0.9747 | 0.8937 | 0.9324 | 0.0232 |
| Random Forest (200 trees) | **0.9751** | **0.9892** | **0.9607** | **0.9747** | **0.0105** |

Thesis (21 features + WHOIS/DNS): RF 0.9768, XGB 0.9856.
v2 loses ~0.2 pts vs thesis RF, ~1 pt vs XGB — with <1ms prediction,
no internet lookups, 10 features you can explain.

## Why this matters for SOC interviews
- "We trade 1 point of accuracy for 200x lower latency and full explainability."
- "FPR 1.05%: ~1 in 100 legit sites flagged. Blocking legit bank = incident,
  so we optimise precision and keep a human-readable reason for every block."
- "LR recall 0.89 vs RF 0.96: phishing patterns are non-linear (IP + hyphens
  + length interact), so trees win. Baseline proves the features carry signal."

## Files
- `data/urls_labelled.csv` — 24,096 rows, 50/50, split train/val/test (from VerifAI)
- `train_model.py --full` — merges val into train (20,481 train / 3,615 test)
- `models/*.joblib` — retrained, gitignored (clone → run --full to reproduce)
