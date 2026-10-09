"""Phase 2: host intelligence (WHOIS age + DNS) with graceful fallback.

Architecture (two-tier, standard practice):
  Tier 1 (always): lexical RF, <1ms, no internet. Decides Legit / Uncertain / Malicious.
  Tier 2 (Uncertain band only, ~4% of traffic): live WHOIS/DNS with hard
  timeouts + persistent cache. Can resolve Uncertain -> Malicious/Legitimate,
  or leave Uncertain with a "host lookup unavailable" note. Confident
  Tier-1 verdicts are NEVER flipped by host rules - only annotated.

Why rules instead of retraining with host features? A full 24k WHOIS crawl
takes hours and rots (domains die, get re-registered). The directional
priors are unambiguous (young + no-DNS = suspicious; old + DNS =
established), so explicit auditable rules beat a stale retrained model.
Script for a future full crawl: docs/03-host-signals.md.

Contract: get_host_signals NEVER raises and NEVER exceeds ~5s wall time
(DNS 3s + WHOIS 4s run in parallel).
Unknowns are -1 (not 0) so "no data" can't impersonate "bad data".
"""
import json
import os
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from datetime import datetime

CACHE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", ".host_cache.json")
DNS_TIMEOUT = 3.0
WHOIS_TIMEOUT = 4.0
YOUNG_DAYS = 90
ESTABLISHED_DAYS = 365

_cache: dict = {}
_cache_loaded = False


def _load_cache():
    global _cache, _cache_loaded
    if _cache_loaded:
        return
    _cache_loaded = True
    try:
        with open(CACHE_PATH) as f:
            _cache = json.load(f)
    except (FileNotFoundError, ValueError):
        _cache = {}


def _save_cache():
    try:
        os.makedirs(os.path.dirname(CACHE_PATH), exist_ok=True)
        with open(CACHE_PATH, "w") as f:
            json.dump(_cache, f)
    except OSError:
        pass  # cache is best-effort; predictions must never fail because of it


def _dns_lookup(host: str) -> int:
    """1 = has A record, 0 = none, -1 = lookup failed/timed out. ONE bounded call."""
    try:
        import dns.resolver
        from dns.resolver import NXDOMAIN, NoAnswer, NoNameservers, LifetimeExceeded, Timeout
        res = dns.resolver.Resolver()
        res.lifetime = DNS_TIMEOUT
        try:
            res.resolve(host, "A")
            return 1
        except (NXDOMAIN, NoAnswer, NoNameservers):
            return 0
        except (LifetimeExceeded, Timeout):
            return -1
    except Exception:
        return -1
    return -1


_whois_pool = None


def _pool():
    """Singleton worker pool for WHOIS (recreated after a timeout-shutdown)."""
    global _whois_pool
    if _whois_pool is None:
        _whois_pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="whois")
    return _whois_pool


def _whois_age(host: str) -> float:
    """Domain age in days, or -1.0 if unavailable. NEVER waits more than WHOIS_TIMEOUT.

    Why a singleton pool + shutdown instead of `with`: exiting a `with` pool
    BLOCKS until the hung socket worker dies (OS connect timeout, ~11s here),
    defeating fut.result(timeout). shutdown(wait=False) detaches the hung
    worker (reaped by the OS shortly after); the pool is then recreated.
    Cost: one stray thread per timed-out lookup. Requests never wait.
    """
    def _fetch():
        import whois
        w = whois.whois(host)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        if isinstance(created, str):
            created = datetime.strptime(created, "%Y-%m-%d")
        if not created:
            return -1.0
        return float((datetime.now() - created).days)

    global _whois_pool
    try:
        fut = _pool().submit(_fetch)
        return float(fut.result(timeout=WHOIS_TIMEOUT))
    except (FutureTimeout, Exception):
        try:
            _whois_pool.shutdown(wait=False, cancel_futures=True)
        except Exception:
            pass
        _whois_pool = None
        return -1.0


def get_host_signals(hostname: str) -> dict:
    """Cached, bounded, never-raising host intel for one hostname."""
    host = (hostname or "").lower().strip().lstrip(".")
    if not host:
        return {"host": host, "domain_age_days": -1.0, "dns_found": -1,
                "source": "invalid", "latency_ms": 0}
    _load_cache()
    if host in _cache:
        hit = dict(_cache[host])
        hit["source"] = "cache"
        hit["latency_ms"] = 0
        return hit
    t0 = time.time()
    # DNS + WHOIS in parallel: wall time ~= max(dns, whois), not the sum.
    with ThreadPoolExecutor(max_workers=2) as pool:
        dns_fut = pool.submit(_dns_lookup, host)
        age_fut = pool.submit(_whois_age, host)
        dns = dns_fut.result()
        age = age_fut.result()
    source = "live" if (dns != -1 or age != -1.0) else "unavailable"
    sig = {"host": host, "domain_age_days": age, "dns_found": dns,
           "source": source, "latency_ms": int((time.time() - t0) * 1000)}
    _cache[host] = {k: v for k, v in sig.items() if k not in ("source", "latency_ms")}
    _save_cache()
    return sig


def adjust_with_host(verdict: str, proba_mal: float, signals: dict):
    """Apply Tier-2 rules. Returns (verdict, host_factors list).

    Only resolves Uncertain. Confident verdicts get annotations, never flips.
    """
    age = signals.get("domain_age_days", -1.0)
    dns = signals.get("dns_found", -1)
    host = signals.get("host", "?")
    source = signals.get("source", "?")
    factors = []

    if source == "unavailable":
        factors.append({"feature": "host_lookup", "value": -1, "source": "host",
                        "reason": "Host lookup unavailable (no WHOIS/DNS response) - verdict rests on URL analysis alone."})
        return verdict, factors

    young = 0 <= age <= YOUNG_DAYS
    established = age >= ESTABLISHED_DAYS
    no_dns = dns == 0
    has_dns = dns == 1

    if young:
        factors.append({"feature": "domain_age_days", "value": age, "source": "host",
                        "reason": f"Host intel: domain is {int(age)} days old - newborn domains dominate phishing campaigns."})
    if no_dns:
        factors.append({"feature": "dns_record", "value": 0, "source": "host",
                        "reason": "Host intel: no DNS record - the domain does not resolve right now."})
    if established and has_dns:
        factors.append({"feature": "domain_age_days", "value": age, "source": "host",
                        "reason": f"Host intel: domain established {int(age)} days with valid DNS - long-lived infrastructure."})

    if verdict == "Uncertain":
        if young or no_dns:
            return "Malicious", factors
        if established and has_dns:
            return "Legitimate", factors
    return verdict, factors
