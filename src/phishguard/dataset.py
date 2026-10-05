"""Synthetic labelled URL corpus.

Benign URLs are built from popular real domains with realistic paths (including hard cases
such as legitimate login pages and long tracking URLs). Phishing URLs reproduce the techniques
documented in APWG / PhishTank reports: typosquatting, brand-in-subdomain, IP hosts, '@' tricks,
shorteners, punycode, free hosting and random subdomains.
"""
from __future__ import annotations

import random
import string

from .features import BRANDS, KEYWORDS, SHORTENERS, SUSPICIOUS_TLDS

POPULAR = [
    "google.com", "youtube.com", "wikipedia.org", "github.com", "stackoverflow.com", "amazon.com",
    "microsoft.com", "apple.com", "paypal.com", "netflix.com", "linkedin.com", "reddit.com",
    "bbc.co.uk", "nytimes.com", "cnn.com", "medium.com", "python.org", "mozilla.org", "dropbox.com",
    "spotify.com", "adobe.com", "salesforce.com", "zoom.us", "slack.com", "atlassian.com",
    "cloudflare.com", "openai.com", "ibm.com", "oracle.com", "nasa.gov", "who.int", "mit.edu",
    "coursera.org", "udemy.com", "booking.com", "airbnb.com", "ebay.com", "etsy.com", "shopify.com",
    "wordpress.org", "w3.org", "docker.com", "kaggle.com", "arxiv.org", "nature.com", "imdb.com",
    "twitch.tv", "instagram.com", "facebook.com", "whatsapp.com", "chase.com", "dhl.com", "fedex.com",
]
WORDS = ["news", "docs", "blog", "help", "en", "products", "article", "search", "watch", "wiki", "about",
         "pricing", "download", "careers", "store", "user", "settings", "learn", "events", "api", "guide"]
FREE_HOSTS = ["000webhostapp.com", "weebly.com", "firebaseapp.com", "glitch.me", "netlify.app",
              "web.app", "pages.dev", "blogspot.com", "wixsite.com", "duckdns.org"]


def _slug(r: random.Random, k: int = 2) -> str:
    return "-".join(r.choice(WORDS) for _ in range(k))


def _rand(r: random.Random, n: int, alphabet: str = string.ascii_lowercase + string.digits) -> str:
    return "".join(r.choice(alphabet) for _ in range(n))


LONGTAIL_TLDS = ["com", "com", "com", "net", "org", "io", "dev", "app", "co", "ma", "fr", "de", "xyz", "info", "online"]


def longtail(r: random.Random) -> str:
    """Small legitimate sites: hyphens, digits, cheap TLDs, PHP pages, plain HTTP - the hard benign cases."""
    name = r.choice([
        f"{r.choice(WORDS)}-{r.choice(WORDS)}", f"{r.choice(WORDS)}{r.randint(1, 365)}",
        f"{r.choice(WORDS)}{r.choice(WORDS)}", f"the-{r.choice(WORDS)}-{r.choice(['shop', 'studio', 'lab', 'club'])}",
    ])
    sub = r.choice(["www.", "", "", "blog.", "shop."])
    path = r.choice(["/", "/index.php", f"/{r.choice(WORDS)}.html", f"/{_slug(r)}/", "/contact.php",
                     f"/?p={r.randint(1, 900)}", "/my-account/login", f"/product/{_slug(r)}-{r.randint(1, 99)}"])
    scheme = "https" if r.random() < 0.8 else "http"
    return f"{scheme}://{sub}{name}.{r.choice(LONGTAIL_TLDS)}{path}"


def benign(r: random.Random) -> str:
    if r.random() < 0.35:
        return longtail(r)
    if r.random() < 0.04:  # shortened links are mostly legitimate marketing links
        return f"https://{r.choice(sorted(SHORTENERS))}/{_rand(r, 7, string.ascii_letters + string.digits)}"
    d = r.choice(POPULAR)
    sub = r.choice(["www.", "", "", "docs.", "en.", "support.", "accounts."])
    kind = r.random()
    if kind < 0.35:
        path = "/" + "/".join(_slug(r, r.randint(1, 2)) for _ in range(r.randint(1, 3)))
    elif kind < 0.55:
        path = f"/{r.choice(WORDS)}?q={_slug(r)}&page={r.randint(1, 20)}"
    elif kind < 0.70:  # hard case: real login pages
        path = r.choice(["/login", "/signin", "/account/settings", "/accounts/login?next=/home", "/auth/verify"])
    elif kind < 0.85:  # hard case: long tracking links
        path = (f"/{_slug(r)}?utm_source={r.choice(WORDS)}&utm_medium=email&utm_campaign={_slug(r)}"
                f"&id={_rand(r, 24)}")
    else:
        path = f"/{r.choice(WORDS)}/{r.randint(1000, 99999)}"
    scheme = "https" if r.random() < 0.95 else "http"
    return f"{scheme}://{sub}{d}{path}"


def _typo(r: random.Random, brand: str) -> str:
    ops = [
        lambda b: b.replace("o", "0", 1), lambda b: b.replace("l", "1", 1), lambda b: b.replace("i", "1", 1),
        lambda b: b + r.choice(["-secure", "-login", "-support", "-verify"]),
        lambda b: b[:-1] + b[-1] * 2, lambda b: b.replace("m", "rn", 1),
        lambda b: r.choice(["my", "secure-", "login-"]) + b,
    ]
    out = r.choice(ops)(brand)
    return out if out != brand else brand + "-account"


def phishing(r: random.Random) -> str:
    brand = r.choice(BRANDS)
    kw = r.choice(KEYWORDS)
    tld = r.choice(sorted(SUSPICIOUS_TLDS) + ["com", "net", "info", "online", "site"])
    t = r.random()
    if t < 0.18:
        host = f"{brand}.com.{kw}-{_rand(r, 5)}.{tld}"
    elif t < 0.34:
        host = f"{_typo(r, brand)}.{r.choice(['com', 'net', tld])}"
    elif t < 0.44:
        host = ".".join(str(r.randint(1, 254)) for _ in range(4))
        if r.random() < 0.5:
            return f"http://{host}/{r.choice([kw, brand, _rand(r, 4)])}"
    elif t < 0.52:
        ip = ".".join(str(r.randint(1, 254)) for _ in range(4))
        target = r.choice([_rand(r, r.randint(1, 10)), r.choice(WORDS), ip])
        tail = r.choice([f"/{kw}", f"/{kw}/{_rand(r, 10)}", "/", ""])
        return f"{r.choice(['http', 'https'])}://{brand}.com@{target}.{tld}{tail}"
    elif t < 0.60:
        return f"https://{r.choice(sorted(SHORTENERS))}/{_rand(r, 7, string.ascii_letters + string.digits)}"
    elif t < 0.70:
        host = f"{brand}-{kw}-{_rand(r, 6)}.{r.choice(FREE_HOSTS)}"
    elif t < 0.78:
        host = f"xn--{_rand(r, 4)}{brand[:3]}-{_rand(r, 3)}.com"
    elif t < 0.90:
        host = f"{_rand(r, r.randint(10, 22))}.{tld}"
    else:  # hard case: plausible-looking domain, only the path reveals the lure
        host = f"{r.choice(WORDS)}-{r.choice(WORDS)}.com"
    path = r.choice([
        f"/{kw}/{brand}/index.php", f"/{brand}/{kw}.html", f"/wp-content/{_rand(r, 6)}/{kw}.php",
        f"/{kw}?session={_rand(r, 32)}", f"/secure/{kw}/{_rand(r, 12)}", f"/{_rand(r, 8)}/invoice.zip",
        f"//{brand}.com/{kw}",
    ])
    port = f":{r.choice([8080, 8443, 2083])}" if r.random() < 0.06 else ""
    scheme = "https" if r.random() < 0.55 else "http"
    return f"{scheme}://{host}{port}{path}"


def generate(n: int = 10_000, phishing_share: float = 0.4, seed: int = 11) -> tuple[list[str], list[int]]:
    r = random.Random(seed)
    urls, labels = [], []
    for _ in range(n):
        is_phish = r.random() < phishing_share
        urls.append(phishing(r) if is_phish else benign(r))
        labels.append(int(is_phish))
    return urls, labels
