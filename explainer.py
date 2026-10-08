"""Stage 3: numbers + verdict -> plain-English reason.

Honest naming: original called this shap/lime but it was rule-based.
We call it what it is: rules. SOC analysts trust this more than
"SHAP value 0.34" — they want "IP instead of domain + @ trick".

Each rule: if feature crosses threshold, fire with a sentence.
app.py shows top 3.
"""
MALICIOUS_RULES = {
    "has_ip_address": (0.5, "high", "Uses an IP address instead of a domain - classic phishing host."),
    "has_at_symbol": (0.5, "high", "Contains @ - browsers hide everything before @, so real destination is after it."),
    "hyphen_count": (2, "high", "Multiple hyphens - typosquat pattern like pay-pal-secure.com."),
    "dot_count": (4, "high", "Many dots - possible subdomain stacking to fake a trusted brand."),
    "digit_count": (8, "high", "Many digits - auto-generated malicious domains are digit-heavy."),
    "url_length": (75, "high", "Unusually long URL - padding used to hide the real domain."),
    "special_char_count": (20, "high", "Many special chars - obfuscation attempt."),
    "has_https": (0.5, "low", "No HTTPS - unencrypted login/payment is a red flag."),
}

LEGIT_RULES = {
    "has_https": (0.5, "high", "Uses HTTPS - encrypted, domain validated."),
    "has_ip_address": (0.5, "low", "Uses a real domain, not a raw IP."),
    "has_at_symbol": (0.5, "low", "No @ trick detected."),
    "url_length": (60, "low", "Normal URL length."),
    "hyphen_count": (2, "low", "No typosquat hyphens."),
}


def explain(features: dict, is_malicious: bool, confidence: float) -> dict:
    rules = MALICIOUS_RULES if is_malicious else LEGIT_RULES
    hits = []
    for feat, (thresh, direction, text) in rules.items():
        v = features.get(feat, 0)
        fired = (v > thresh) if direction == "high" else (v < thresh)
        if fired:
            hits.append({"feature": feat, "value": v, "reason": text})
    verdict = "Malicious" if is_malicious else "Legitimate"
    if hits:
        summary = f"Verdict: {verdict} ({confidence*100:.1f}%). " + " ".join(h["reason"] for h in hits[:3])
    else:
        summary = f"Verdict: {verdict} ({confidence*100:.1f}%) based on overall pattern."
    return {"verdict": verdict, "summary": summary, "factors": hits[:5]}
