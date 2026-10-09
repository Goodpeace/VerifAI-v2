"""Stage 1: URL string -> 10 numbers. THE most important file.

Mental model for SOC analysts:
  You triage a URL without clicking it. You check: Is it an IP?
  Does it have @? How many hyphens/dots? Does it say https?
  This class does exactly that, automatically.

Original had 21 features (needed WHOIS/DNS internet lookups = 3.8s slow).
v2 uses 10 lexical-only features (no internet, <1ms). Same idea, learnable.
"""
import re
from urllib.parse import urlparse


class URLFeatureExtractor:
    FEATURE_NAMES = [
        "url_length",       # phishing URLs are often padded long to hide real domain
        "domain_length",    # generated domains tend to be long/random
        "path_length",      # long path = obfuscation hiding after domain
        "dot_count",        # many dots = subdomain stacking (pay.google.com.evil.tk)
        "hyphen_count",     # typosquat: pay-pal-secure-login.com
        "digit_count",      # algorithm domains: secure24791.top
        "special_char_count",  # !!!, ___, %%% = obfuscation
        "has_ip_address",   # http://192.168.1.1/login = never legit for banks
        "has_at_symbol",    # http://google.com@evil.com -> browser goes to evil.com
        "has_https",        # 1 if https, 0 otherwise (strongest single signal: 0.68 importance)
    ]

    IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")

    def extract(self, url: str) -> dict:
        # 1. Normalise: lowercase, strip, add https:// if missing.
        # Why https and not http? Browsers (Chrome/Edge since 2021) navigate
        # scheme-less input as https. Assuming http punishes every shortened
        # legit URL ("google.com" -> Malicious) because has_https dominates.
        u = url.lower().strip()
        if "://" not in u:
            u = "https://" + u
        parsed = urlparse(u)
        domain = parsed.hostname or ""
        path = parsed.path or ""

        feats = {}
        feats["url_length"] = float(len(u))
        feats["domain_length"] = float(len(domain))
        feats["path_length"] = float(len(path))
        feats["dot_count"] = float(u.count("."))
        feats["hyphen_count"] = float(u.count("-"))
        feats["digit_count"] = float(sum(c.isdigit() for c in u))
        feats["special_char_count"] = float(len(re.findall(r"[^a-zA-Z0-9]", u)))
        feats["has_ip_address"] = 1.0 if self.IP_RE.match(domain) else 0.0
        feats["has_at_symbol"] = 1.0 if "@" in u else 0.0
        feats["has_https"] = 1.0 if u.startswith("https://") else 0.0
        return feats
