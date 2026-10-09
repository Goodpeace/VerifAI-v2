"""Tier-2 host-intel tests. No network: logic uses stubbed signals;
only the fallback path touches the network (invalid host -> fast fail)."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from host_intel import adjust_with_host, get_host_signals


def test_young_domain_escalates_uncertain():
    sig = {"host": "evil.tk", "domain_age_days": 12.0, "dns_found": 0, "source": "live"}
    v, factors = adjust_with_host("Uncertain", 0.66, sig)
    assert v == "Malicious", v
    assert any(f["source"] == "host" for f in factors)


def test_established_domain_resolves_legitimate():
    sig = {"host": "example.org", "domain_age_days": 4000.0, "dns_found": 1, "source": "live"}
    v, _ = adjust_with_host("Uncertain", 0.50, sig)
    assert v == "Legitimate", v


def test_confident_verdicts_never_flipped():
    sig = {"host": "evil.tk", "domain_age_days": 5.0, "dns_found": 0, "source": "live"}
    v, _ = adjust_with_host("Legitimate", 0.05, sig)
    assert v == "Legitimate", v
    v, _ = adjust_with_host("Malicious", 0.99, sig)
    assert v == "Malicious", v


def test_unavailable_lookup_keeps_verdict():
    sig = {"host": "?", "domain_age_days": -1.0, "dns_found": -1, "source": "unavailable"}
    v, factors = adjust_with_host("Uncertain", 0.60, sig)
    assert v == "Uncertain", v
    assert any("unavailable" in f["reason"] for f in factors)


def test_invalid_host_fails_fast_without_raising():
    import time
    t0 = time.time()
    assert get_host_signals("")["source"] == "invalid"
    sig = get_host_signals("not a host!!!")
    assert sig["source"] in ("invalid", "unavailable", "live", "cache"), sig
    assert time.time() - t0 < 20


if __name__ == "__main__":
    test_young_domain_escalates_uncertain()
    test_established_domain_resolves_legitimate()
    test_confident_verdicts_never_flipped()
    test_unavailable_lookup_keeps_verdict()
    test_invalid_host_fails_fast_without_raising()
    print("5/5 host tests passed")
