# START HERE — VerifAI-v2 in 10 minutes

You said you know literally nothing about the project. Read this first,
then read the code files in this order:

## The core concept (1 paragraph)
Phishing = fake login/payment page with a trick URL.
VerifAI never visits the URL (too dangerous). It looks at the URL
*string* and asks: "does this LOOK like phishing?" — long, many
hyphens, IP instead of domain, `@` trick, `.tk/.top` TLD, words like
`login/verify/pay` in a weird place. A model learns these patterns
from 24k labelled URLs, then a rule engine explains the verdict
in plain English for a SOC analyst.

## Read order (same as data flows)
1. `config.py` — constants (5 lines that matter)
2. `feature_extractor.py` — URL string -> 10 numbers (THE key file)
3. `train_model.py` — numbers + labels -> saved model
4. `explainer.py` — numbers + verdict -> English reason
5. `database.py` — save every verdict (SOC audit trail)
6. `app.py` — Flask glue: `/predict` + pages

## Stages
- Stage 1 (this repo): lexical-only, 20 URLs, 2 models. Runs in 30 sec.
- Stage 2: add your 24k CSV back, retrain, compare metrics.
- Stage 3: add XGBoost + cross-validation (original thesis Ch.4).
- Stage 4: add WHOIS/DNS host features (and feel the 3.8s latency pain).
- Stage 5: Docker + deploy (Render/Fly) — required for Tokyo/SG jobs.

## Why simplified?
Original: 21 features, 8 root scripts, shap/lime/whois/dns/xgboost.
Interviewers in Tokyo/Singapore reject messy roots. They hire:
clean structure, tests, Docker, English README, live demo link.
v2 gives you that. Original stays untouched in `Goodpeace/VerifAI`.
