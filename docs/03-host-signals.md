# Tier 2: host signals — design + proof (Phase 2)

## Architecture
- Tier 1 (all traffic): lexical RF, <1ms, no internet.
- Tier 2 (Uncertain band only, ~3.8%): live DNS + WHOIS, then rules:
  - young (<=90d) or no-DNS -> Uncertain becomes Malicious (conf 75, host-escalated)
  - established (>=365d) + DNS -> Uncertain becomes Legitimate
  - lookup unavailable -> verdict stands, note appended
  - confident Tier-1 verdicts are NEVER flipped, only annotated (asserted in tests)

## Why rules, not retraining
A 24k WHOIS crawl takes hours and rots within weeks (domains die, re-register).
Directional priors are unambiguous, so explicit auditable rules beat a stale
model. Revisit only with a continuously refreshed crawl (script sketch below).

## Latency contract (measured, sandbox with no port-43 route)
- DNS: single bounded dnspython call, 0.2s here.
- WHOIS: singleton pool + shutdown(wait=False) recreation; `with`-pool was
  measured hanging 10.9s (exit waits for the dead socket). Now exactly 4.0s.
- Wall total ~= max(dns, whois) via parallel submit: **4.0s measured**.
- Only ~4% of requests pay this. Median stays <1ms.

## Proof
- 5/5 host tests (stubbed signals, no network) + 7/7 existing: `python tests/test_host.py`
- Live sandbox run: `.tk` phish, DNS fail + WHOIS timeout -> "unavailable",
  verdict honestly stays Uncertain (on Render with real network: DNS 0 -> Malicious 75).
- Cache: `data/.host_cache.json` (gitignored), repeat hosts cost 0ms.

## Future full-crawl sketch (if retraining with host features one day)
for host in train_hosts: signals = get_host_signals(host) # cached, resumable
append domain_age_days/dns_found as features 11-12, retrain, re-tune threshold.
Do NOT crawl test hosts before final eval (leakage via cache timestamps is
negligible, but keep the discipline anyway).
