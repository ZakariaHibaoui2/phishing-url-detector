# PhishGuard — Explainable Phishing URL Detection

> Classifies URLs as **phishing / suspicious / legitimate** without visiting them, using 28 engineered features, gradient boosting, and a layer of high-severity rules. Every verdict comes with plain-language reasons.

[![CI](https://github.com/ZakariaHibaoui2/phishing-url-detector/actions/workflows/ci.yml/badge.svg)](https://github.com/ZakariaHibaoui2/phishing-url-detector/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)
![scikit-learn](https://img.shields.io/badge/scikit--learn-F7931E?logo=scikitlearn&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-009688?logo=fastapi&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green)

---

## Demo

```text
$ phishguard check https://github.com/explore http://paypal.com@x.top/login \
    https://micros0ft-support.com/account/verify https://bit.ly/3Kx9 https://my-bakery-shop.ma/contact.php

[OK]            0.0%  https://github.com/explore
[PHISHING]    100.0%  http://paypal.com@x.top/login
                     - '@' in the authority hides the real destination
                     - top-level domain frequently abused for phishing
                     - not using HTTPS
[PHISHING]    100.0%  https://micros0ft-support.com/account/verify
                     - domain imitates a well-known brand (typosquatting)
                     - 3 credential-lure keywords (login, verify, account...)
[SUSPICIOUS]   70.0%  https://bit.ly/3Kx9
                     - URL shortener hides the destination
[OK]            0.0%  https://my-bakery-shop.ma/contact.php
```

## How it works

```
URL ──► 28 features ──► HistGradientBoosting ──► P(phishing)
         │                                            │
         └──► high-severity rules (score floors) ─────┴──► max() ──► verdict + reasons
```

**Features** (no DNS/HTTP needed, so it's safe and fast):

| Group | Examples |
|---|---|
| Structure | URL / host / path / query length, dots, path depth, query params, `%` encoding |
| Obfuscation | IP host (incl. hex/decimal), `@` in authority, non-standard port, `//` redirect, punycode (`xn--`) |
| Brand abuse | brand in subdomain or path (`paypal.com.verify-x.top`), **lookalikes** via Levenshtein + homoglyph normalisation (`micros0ft`, `app1e`, `rnicrosoft`) |
| Lexical | credential-lure keywords, host entropy, digit ratio, vowel ratio, longest token |
| Reputation-free signals | suspicious TLDs, URL shorteners, risky file extensions |

**Defence in depth:** indicators that are almost never legitimate (`@` trick, brand-in-subdomain, lookalike, punycode, IP host) set a **minimum score**, so an ML blind spot can't let them through.

## Results

`phishguard evaluate -n 20000` (stratified 75/25 split):

| Metric | Value |
|---|---|
| Accuracy | 0.984 |
| Precision | 0.963 |
| Recall | **0.998** |
| F1 | 0.980 |
| ROC-AUC | 0.999 |

Most influential features (permutation importance): subdomain depth, brand outside the registered domain, lure keywords, URL length, shorteners, `@`.

The training corpus is synthetic but deliberately hard (see `dataset.py`): benign URLs include **real login pages, long tracking links, small hyphenated / numeric sites on cheap TLDs, PHP pages, plain HTTP, and legitimate short links**. Phishing URLs reproduce the techniques catalogued by APWG/PhishTank. For production, retrain on a labelled feed (e.g. PhishTank + Tranco top sites) with `PhishGuard().fit(urls, labels)`.

## Usage

```bash
pip install -e ".[dev]"

phishguard check <url> [<url> ...]          # human-readable
phishguard check --json <url>                # JSON
cat urls.txt | phishguard check -            # from stdin
phishguard evaluate                          # metrics + feature importance
phishguard train -o phishguard.joblib        # persist a model
phishguard serve                             # REST API on :8000
```

| Method | Path | Body |
|---|---|---|
| GET | `/health` | none |
| POST | `/check` | `{"url": "..."}` |
| POST | `/check/batch` | `["url1", "url2", ...]` (max 1000) |

```bash
docker build -t phishguard . && docker run -p 8000:8000 phishguard
```

## Project structure

```
src/phishguard/
├── features.py   # 28 features, lookalike detection, explanations
├── dataset.py    # synthetic labelled corpus with hard benign cases
├── model.py      # PhishGuard (GBM + rule floors), evaluation, permutation importance
├── api.py        # FastAPI
└── cli.py        # check / train / evaluate / serve
tests/            # 20 tests: feature red flags, metrics, known URLs, persistence, CLI, API
```

## License

[MIT](LICENSE)
