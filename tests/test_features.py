"""Run: python -m pytest tests/ -v  (or: python -m pytest)
If pytest missing: pip install pytest — or just run python tests/test_features.py
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from feature_extractor import URLFeatureExtractor

def test_ip_flagged():
    e = URLFeatureExtractor()
    assert e.extract("http://192.168.1.1/login.php")["has_ip_address"] == 1.0

def test_at_trick_flagged():
    e = URLFeatureExtractor()
    assert e.extract("http://google.com@evil.com")["has_at_symbol"] == 1.0

def test_https_detected():
    e = URLFeatureExtractor()
    assert e.extract("https://www.google.com")["has_https"] == 1.0
    assert e.extract("http://example.com")["has_https"] == 0.0

def test_bare_domain_defaults_to_https():
    # Regression: "google.com" must analyse as https (browsers do this).
    # Old http default made EVERY shortened legit URL read Malicious.
    e = URLFeatureExtractor()
    assert e.extract("google.com")["has_https"] == 1.0
    assert e.extract("kpmg.com")["has_https"] == 1.0

def test_contributions_are_exact():
    # Non-sloppy core: bias + sum(contributions) == model probability.
    import numpy as np, joblib
    from config import RF_PATH, FEATURE_COLUMNS
    from explainer import tree_contributions
    rf = joblib.load(RF_PATH)
    e = URLFeatureExtractor()
    for u in ["https://www.google.com", "http://192.168.1.1/login.php",
              "https://secure-login-paypal-verification.tk/account/signin"]:
        f = e.extract(u)
        vec = np.array([[f[c] for c in FEATURE_COLUMNS]])
        b, c = tree_contributions(rf, vec)
        p = float(rf.predict_proba(vec)[0][1])
        assert abs((b + sum(c.values())) - p) < 1e-9, u

def test_no_many_dots_for_one_dot():
    # Truthfulness: never render "Many dots (1.0)".
    from explainer import _sentence
    s, _ = _sentence("dot_count", 1.0, 0.3)
    assert "Many dots" not in s, s

def test_review_band_exists():
    # Operating contract: mid scores are Uncertain, never forced.
    from explainer import explain
    assert explain({}, 0.66)["verdict"] == "Uncertain"
    assert explain({}, 0.99)["verdict"] == "Malicious"
    assert explain({}, 0.05)["verdict"] == "Legitimate"

if __name__ == "__main__":
    test_ip_flagged(); test_at_trick_flagged(); test_https_detected()
    test_bare_domain_defaults_to_https()
    test_contributions_are_exact()
    test_no_many_dots_for_one_dot()
    test_review_band_exists()
    print("7/7 tests passed (4 feature + 3 explanation)")
