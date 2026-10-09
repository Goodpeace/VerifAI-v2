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

if __name__ == "__main__":
    test_ip_flagged(); test_at_trick_flagged(); test_https_detected()
    test_bare_domain_defaults_to_https()
    print("4/4 feature tests passed")
