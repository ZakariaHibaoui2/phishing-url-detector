"""URL feature engineering (no network access required)."""
from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from urllib.parse import unquote, urlsplit

BRANDS = [
    "paypal", "apple", "microsoft", "office365", "outlook", "google", "gmail", "amazon", "netflix",
    "facebook", "instagram", "whatsapp", "linkedin", "dropbox", "docusign", "chase", "wellsfargo",
    "bankofamerica", "dhl", "fedex", "ups", "binance", "coinbase", "steam", "adobe", "icloud",
]
KEYWORDS = [
    "login", "signin", "verify", "verification", "secure", "account", "update", "confirm", "banking",
    "password", "unlock", "suspended", "billing", "invoice", "wallet", "recover", "support", "webscr",
]
SHORTENERS = {"bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rb.gy"}
SUSPICIOUS_TLDS = {"xyz", "top", "zip", "click", "country", "gq", "tk", "ml", "cf", "ga", "work", "rest",
                   "support", "live", "icu", "buzz", "monster", "cam", "mov"}
RISKY_EXT = (".exe", ".scr", ".zip", ".js", ".apk", ".msi", ".bat", ".php", ".html")

FEATURE_NAMES = [
    "url_length", "host_length", "path_length", "query_length", "num_dots", "num_hyphens",
    "num_digits_ratio", "num_special", "num_subdomains", "is_ip_host", "has_at", "has_port",
    "is_https", "host_entropy", "keyword_hits", "brand_in_subdomain_or_path", "brand_lookalike",
    "punycode", "shortener", "suspicious_tld", "double_slash_redirect", "path_depth",
    "risky_extension", "percent_encoded", "longest_token", "query_params", "digits_in_host",
    "vowel_ratio_host",
]


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    return -sum(c / len(s) * math.log2(c / len(s)) for c in counts.values())


def _levenshtein(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "@": "a"})


def is_lookalike(name: str) -> bool:
    """True if a registered name imitates a brand: typos, homoglyphs (0->o, 1->l) or brand+suffix."""
    candidates = {name, name.translate(HOMOGLYPHS), name.replace("rn", "m"), name.replace("vv", "w")}
    for token in list(candidates):
        candidates.update(t for t in token.split("-") if len(t) >= 4)
    for cand in candidates:
        for b in BRANDS:
            if cand == b and name != b:
                return True
            close = 0 < _levenshtein(cand, b) <= (1 if len(b) <= 5 else 2)
            if len(cand) >= 4 and abs(len(cand) - len(b)) <= 2 and close:
                return True
    return False


def normalise(url: str) -> str:
    url = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url
    return url


def split_host(host: str) -> tuple[str, str, str]:
    """Return (subdomain, registered_name, tld) with a simple public-suffix heuristic."""
    parts = host.split(".")
    if len(parts) >= 3 and parts[-2] in {"co", "com", "org", "net", "ac", "gov", "edu"} and len(parts[-1]) == 2:
        return ".".join(parts[:-3]), parts[-3], ".".join(parts[-2:])
    if len(parts) >= 2:
        return ".".join(parts[:-2]), parts[-2], parts[-1]
    return "", host, ""


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(re.fullmatch(r"0x[0-9a-f]+|\d{8,10}", host))


def extract(url: str) -> dict[str, float]:
    raw = normalise(url)
    parts = urlsplit(raw)
    host = (parts.hostname or "").lower()
    path, query = parts.path or "", parts.query or ""
    sub, name, tld = split_host(host)
    lower = unquote(raw).lower()

    brand_elsewhere = any(b in sub or b in path.lower() for b in BRANDS) and name not in BRANDS
    lookalike = int(name not in BRANDS and is_lookalike(name))
    tokens = re.split(r"[/\.\-_?=&]", lower)
    letters = [c for c in host if c.isalpha()]

    try:
        has_port = int(parts.port is not None)
    except ValueError:
        has_port = 1

    return {
        "url_length": len(raw),
        "host_length": len(host),
        "path_length": len(path),
        "query_length": len(query),
        "num_dots": raw.count("."),
        "num_hyphens": host.count("-"),
        "num_digits_ratio": sum(c.isdigit() for c in raw) / max(len(raw), 1),
        "num_special": sum(raw.count(c) for c in "@~%=&!*$;"),
        "num_subdomains": len(sub.split(".")) if sub else 0,
        "is_ip_host": int(_is_ip(host)),
        "has_at": int("@" in parts.netloc),
        "has_port": has_port,
        "is_https": int(parts.scheme == "https"),
        "host_entropy": _entropy(host),
        "keyword_hits": sum(k in lower for k in KEYWORDS),
        "brand_in_subdomain_or_path": int(brand_elsewhere),
        "brand_lookalike": lookalike,
        "punycode": int("xn--" in host),
        "shortener": int(host in SHORTENERS),
        "suspicious_tld": int(tld.split(".")[-1] in SUSPICIOUS_TLDS),
        "double_slash_redirect": int("//" in raw[8:]),
        "path_depth": path.count("/"),
        "risky_extension": int(path.lower().endswith(RISKY_EXT)),
        "percent_encoded": raw.count("%"),
        "longest_token": max((len(t) for t in tokens), default=0),
        "query_params": len([p for p in query.split("&") if p]),
        "digits_in_host": sum(c.isdigit() for c in host),
        "vowel_ratio_host": (sum(c in "aeiou" for c in letters) / len(letters)) if letters else 0.0,
    }


def vectorize(urls: list[str]) -> list[list[float]]:
    return [[float(f[n]) for n in FEATURE_NAMES] for f in map(extract, urls)]


def reasons(feats: dict[str, float]) -> list[str]:
    """Plain-language red flags, used to explain a verdict."""
    out = []
    checks = [
        ("is_ip_host", "host is a raw IP address"),
        ("has_at", "'@' in the authority hides the real destination"),
        ("brand_in_subdomain_or_path", "a well-known brand appears outside the registered domain"),
        ("brand_lookalike", "domain imitates a well-known brand (typosquatting)"),
        ("punycode", "punycode host (possible homograph attack)"),
        ("shortener", "URL shortener hides the destination"),
        ("suspicious_tld", "top-level domain frequently abused for phishing"),
        ("double_slash_redirect", "embedded '//' redirect"),
        ("risky_extension", "links directly to an executable/script/archive"),
        ("has_port", "non-standard port in URL"),
    ]
    out += [msg for key, msg in checks if feats[key]]
    if feats["keyword_hits"] >= 2:
        out.append(f"{int(feats['keyword_hits'])} credential-lure keywords (login, verify, account...)")
    if feats["num_subdomains"] >= 3:
        out.append(f"deep subdomain chain ({int(feats['num_subdomains'])} levels)")
    if feats["host_entropy"] > 3.8:
        out.append("random-looking host name")
    if not feats["is_https"]:
        out.append("not using HTTPS")
    return out
