# Model Card — VerifAI-v2 Random Forest triage model

## Intended use
SOC-analyst triage of suspicious URLs: Malicious / Uncertain / Legitimate
with plain-English reasons. Triage aid, NOT a sole blocker. Uncertain band
(0.40-0.95) requires human review by design.

## Training data
- `data/urls_labelled.csv`: 24,096 URLs, 50/50 malicious/legitimate,
  pre-split train 16,866 / val 3,615 / test 3,615 (from thesis VerifAI).
- Train = train+val (20,481) + 18,626 host-only augmented twins (train-only,
  never test). 10 lexical features, no target URL ever fetched.

## Metrics (unseen test, 3,615 URLs, operating thr=0.95 tuned out-of-fold)
acc 95.19% · prec 99.82% · rec 90.54% · **FPR 0.17% (3 FP)** · AUC 0.9929
5-fold CV acc 97.77% ± 0.10%. At thr=0.50 (capability reference): acc 97.57%.

## Limitations (do not hide these in interviews)
1. Valid-cert phishing: lexical-only leans on has_https (0.68 importance);
   partial cover via Tier-2 host intel, residual risk remains.
2. Long-path legit (e.g. github file URLs) borderline -> review band.
3. Bare short domains carry uncertainty (google.com p=0.47) -> review band.
4. Training labels reflect 2024-25 feeds; drift expected - retrain cadence needed.
5. No JavaScript/content analysis, no IDN homograph detection yet.

## Ethics / safety
- Never fetches the target URL (string + metadata only).
- Rate-limited public demo (30/min); audit trail in SQLite.
- False positives block legitimate access: operating point minimises FPR,
  Uncertain never auto-blocks.
