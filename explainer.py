"""Stage 3 (standard-grade): model-faithful explanations, no new dependencies.

How it works (exact, not heuristic):
  A Random Forest probability is the mean leaf probability over its trees.
  Walk each tree's decision path for this URL: every split moves the running
  probability (e.g. has_https=0 moves 0.50 -> 0.81). That delta IS the split
  feature's contribution on that tree. Average over all trees:
      bias + sum(contributions) == model predict_proba   (exact, asserted in tests)
  Top positive contributions = "why malicious", top negative = "why legitimate".
  Each is rendered into plain English via TEMPLATES below.

Why not SHAP? SHAP's TreeExplainer computes the same family of additive
contributions but needs numba/llvmlite (~42MB native, failed to download
here, bloats Docker). This is exact path-attribution in ~40 lines of sklearn.

Verdict logic lives here too (single source of truth, loaded from
models/threshold.json written by tune_threshold.py):
  p >= threshold      -> Malicious   (threshold tuned for ~0.5% FPR)
  REVIEW_LO <= p < thr -> Uncertain  (SOC manual-review band, not a guess)
  p < REVIEW_LO       -> Legitimate
"""
import json
import os

import numpy as np

from config import FEATURE_COLUMNS, MODEL_DIR

THRESHOLD_PATH = os.path.join(MODEL_DIR, "threshold.json")
DEFAULT_THRESHOLD = 0.50
REVIEW_LO = 0.40

# Value above which a count feature is suspicious ON ITS OWN. Below the cut,
# a malicious-direction contribution is only meaningful in combination -
# and the sentence must say so (never "Many dots (1.0)").
COUNT_CUTS = {
    "hyphen_count": 2,
    "dot_count": 4,
    "digit_count": 8,
    "url_length": 75,
    "domain_length": 30,
    "path_length": 50,
    "special_char_count": 20,
}
COUNT_LABELS = {
    "hyphen_count": "Hyphen count",
    "dot_count": "Dot count",
    "digit_count": "Digit count",
    "url_length": "URL length",
    "domain_length": "Domain length",
    "path_length": "Path length",
    "special_char_count": "Special-character count",
}


def _sentence(feat: str, value: float, contribution: float) -> tuple[str, str]:
    """Truthful (sentence, direction). Never claims 'many X' for small X."""
    mal_dir, leg_dir = TEMPLATES[feat]
    if contribution > 0:
        cut = COUNT_CUTS.get(feat)
        if cut is not None and value <= cut:
            label = COUNT_LABELS[feat]
            return (f"{label} is {value:g} - normal on its own; the model reads it "
                    f"as phishing-leaning only in combination with the stronger signals."), "malicious"
        try:
            return mal_dir.format(value=value), "malicious"
        except KeyError:
            return mal_dir, "malicious"
    return leg_dir, "legitimate"
TEMPLATES = {
    "has_ip_address": (
        "Uses an IP address ({value}) instead of a domain name - hosts that hide behind raw IPs are a classic phishing pattern.",
        "Uses a proper domain name instead of a raw IP address.",
    ),
    "has_at_symbol": (
        "Contains an @ symbol - browsers ignore everything before it, so the real destination is hidden after the @.",
        "No @ trick detected.",
    ),
    "has_https": (
        "No HTTPS - login or payment over unencrypted HTTP is a red flag.",
        "Uses HTTPS - the connection is encrypted and the domain was issued a certificate.",
    ),
    "hyphen_count": (
        "Multiple hyphens ({value}) - typosquat pattern such as pay-pal-secure-login.com.",
        "No typosquat-style hyphen stacking.",
    ),
    "dot_count": (
        "Many dots ({value}) - consistent with subdomain stacking used to fake trusted brands.",
        "Normal dot count - no deceptive subdomain nesting.",
    ),
    "digit_count": (
        "Many digits ({value}) - auto-generated malicious domains are digit-heavy.",
        "Normal digit count.",
    ),
    "url_length": (
        "Unusually long URL ({value} chars) - padding is used to push the real domain out of view.",
        "URL length is within the normal range.",
    ),
    "domain_length": (
        "Unusually long domain ({value} chars) - generated domains skew long and random.",
        "Domain length is typical.",
    ),
    "path_length": (
        "Very long path ({value} chars) after the domain - a common obfuscation technique.",
        "Short, typical path.",
    ),
    "special_char_count": (
        "Many special characters ({value}) - consistent with deliberate obfuscation.",
        "Normal special-character count - no obfuscation pattern.",
    ),
}


def load_threshold() -> float:
    try:
        with open(THRESHOLD_PATH) as f:
            return float(json.load(f)["threshold"])
    except (FileNotFoundError, KeyError, ValueError):
        return DEFAULT_THRESHOLD


def tree_contributions(rf_model, vector: np.ndarray):
    """Exact per-feature contributions to P(malicious) for one sample.

    Returns (bias, {feature: contribution}). bias + sum == predict_proba[1].
    """
    x = np.asarray(vector, dtype=float).reshape(1, -1)
    contribs = {c: 0.0 for c in FEATURE_COLUMNS}
    biases = []
    for tree in rf_model.estimators_:
        t = tree.tree_
        node_path = tree.decision_path(x).indices
        vals = t.value[:, 0, :]
        totals = vals.sum(axis=1)
        proba = np.divide(vals[:, 1], totals, out=np.zeros_like(totals, dtype=float), where=totals > 0)
        biases.append(float(proba[node_path[0]]))
        for parent, child in zip(node_path[:-1], node_path[1:]):
            feat_idx = t.feature[parent]
            if feat_idx >= 0:  # -2 == leaf, no split
                contribs[FEATURE_COLUMNS[feat_idx]] += float(proba[child] - proba[parent])
    n = len(rf_model.estimators_)
    contribs = {k: v / n for k, v in contribs.items()}
    return sum(biases) / n, contribs


def explain(features: dict, proba_mal: float, rf_model=None) -> dict:
    """Explain one prediction. Returns verdict + English factors.

    If rf_model is given, factors come from exact tree contributions
    (method="tree-contributions"). Otherwise falls back to the legacy
    rule templates (method="rules-fallback", e.g. LR path).
    """
    threshold = load_threshold()
    if proba_mal >= threshold:
        verdict = "Malicious"
    elif proba_mal >= REVIEW_LO:
        verdict = "Uncertain"
    else:
        verdict = "Legitimate"

    factors = []
    method = "rules-fallback"
    if rf_model is not None:
        method = "tree-contributions"
        vec = np.array([[features[c] for c in FEATURE_COLUMNS]])
        _, contribs = tree_contributions(rf_model, vec)
        # Toward-verdict contributions first: positive if Malicious, negative if Legitimate.
        toward = sorted(contribs.items(), key=lambda kv: kv[1], reverse=(verdict == "Malicious"))
        if verdict == "Uncertain":
            toward = sorted(contribs.items(), key=lambda kv: abs(kv[1]), reverse=True)
        for feat, c in toward[:5]:
            if abs(c) < 1e-6:
                continue
            sentence, direction = _sentence(feat, features[feat], c)
            factors.append({
                "feature": feat,
                "value": float(features[feat]),
                "contribution": round(float(c), 4),
                "direction": direction,
                "reason": sentence,
            })

    if verdict == "Uncertain":
        summary = (
            f"Verdict: Uncertain ({proba_mal * 100:.1f}% malicious, threshold {threshold:.2f}). "
            f"This URL sits in the manual-review band - do not trust or block on this score alone. "
            + ("Strongest mixed signals: " + "; ".join(f["reason"] for f in factors[:2]) if factors else "No dominant signal.")
        )
    elif verdict == "Malicious":
        summary = (
            f"Verdict: Malicious ({proba_mal * 100:.1f}% malicious). "
            + (" ".join(f["reason"] for f in factors[:3]) if factors else "Overall feature pattern matches phishing.")
        )
    else:
        summary = (
            f"Verdict: Legitimate ({(1 - proba_mal) * 100:.1f}% legitimate). "
            + (" ".join(f["reason"] for f in factors[:3]) if factors else "Overall feature pattern matches legitimate sites.")
        )
    return {"verdict": verdict, "summary": summary, "factors": factors,
            "method": method, "threshold": threshold}
