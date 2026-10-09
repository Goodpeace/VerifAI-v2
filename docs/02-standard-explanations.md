# Standard-grade explanations — spec + proof (Phase 1)

## What changed and why
Hand-written rules could disagree with the model (they fired on thresholds
the model never learned). Now every cited reason is an **exact per-tree
path contribution**: walk each tree, attribute each probability delta to
its split feature, average over trees. `bias + sum == predict_proba`
to machine epsilon (asserted in tests, max_err 3.3e-16).

SHAP was evaluated and rejected: same additive family, but needs
numba/llvmlite (~42MB native, undownloadable here, Docker bloat).
This is ~40 lines of sklearn, <5ms, zero new dependencies.

## Operating point (minimise false alarms)
`tune_threshold.py` scans thresholds on a fixed 80/20 split of TRAIN
(test set untouched; single split, seed 42 - chosen over 5-fold OOF so the
Docker build fits in 512MB). 0.5% FPR was unreachable below 0.95:
thr=0.95 -> val FPR 0.62%, recall 89.3%. Final unseen TEST@0.95:
**acc 95.19%, prec 99.82%, rec 90.54%, FPR 0.17% (3 FP / 3615)**,
review-band rate 3.8%. Price of near-zero false alarms: ~9% of phish
land in Uncertain for human review instead of auto-block. Documented,
not hidden.

## Verdict contract
- p >= 0.95 -> Malicious (auto-block candidate)
- 0.40 <= p < 0.95 -> Uncertain (manual review, mixed signals shown)
- p < 0.40 -> Legitimate

## Faithfulness (are reasons causal, not decoration?)
Perturbation test, 145 malicious test URLs: set the top-cited factor to
its legit-median value -> P(malicious) drops **0.59 mean, 91% flip rate**.
Cited reasons move the model. Proof script: Temp/opencode/verify_phase1.py.

## Truthfulness rule
Templates are value-aware: below the suspicious cut a factor is reported
as "normal on its own; phishing-leaning only in combination" — never
"Many dots (1.0)". Asserted by test_no_many_dots_for_one_dot.

## Remaining known gaps (Phase 2/3)
- Valid-cert phishing (https + clean lexical) still reads Legit/Uncertain:
  needs host signals (WHOIS age, DNS) with fallback.
- Long-path legit (github URLs) borderline: needs allowlist/review-band UX.
