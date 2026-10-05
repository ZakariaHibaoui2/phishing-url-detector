import pytest
from fastapi.testclient import TestClient

from phishguard.cli import main
from phishguard.dataset import generate
from phishguard.features import FEATURE_NAMES, extract, split_host
from phishguard.model import PhishGuard, evaluate


@pytest.fixture(scope="module")
def model():
    urls, labels = generate(6_000, seed=3)
    return PhishGuard().fit(urls, labels)


def test_feature_vector_complete():
    f = extract("https://www.example.com/a/b?x=1")
    assert list(f) == FEATURE_NAMES
    assert f["is_https"] == 1 and f["path_depth"] == 2 and f["query_params"] == 1


@pytest.mark.parametrize("url,key", [
    ("http://192.168.10.5/login", "is_ip_host"),
    ("http://paypal.com@evil.xyz/x", "has_at"),
    ("https://paypal.com.verify-account.top/x", "brand_in_subdomain_or_path"),
    ("https://paypa1.com/signin", "brand_lookalike"),
    ("https://xn--pypal-4ve.com/", "punycode"),
    ("https://bit.ly/3xYz", "shortener"),
    ("http://site.com/files/update.exe", "risky_extension"),
])
def test_red_flags(url, key):
    assert extract(url)[key] == 1


def test_split_host_handles_cc_slds():
    assert split_host("news.bbc.co.uk") == ("news", "bbc", "co.uk")
    assert split_host("a.b.example.com") == ("a.b", "example", "com")


def test_real_brand_is_not_lookalike():
    assert extract("https://www.paypal.com/signin")["brand_lookalike"] == 0


def test_metrics():
    r = evaluate(8_000, seed=5)
    assert r["f1"] > 0.95 and r["roc_auc"] > 0.98


@pytest.mark.parametrize("url", [
    "http://paypal.com.secure-login-8ff2.xyz/webscr/index.php",
    "http://203.0.113.9/microsoft/verify.html",
    "https://app1e-verify.net/account/update",
])
def test_known_phishing_flagged(model, url):
    r = model.check(url)
    assert r.verdict in {"phishing", "suspicious"}
    assert r.reasons


@pytest.mark.parametrize("url", [
    "https://github.com/explore",
    "https://en.wikipedia.org/wiki/Computer_security",
    "https://accounts.google.com/signin",
])
def test_known_benign_passes(model, url):
    assert model.check(url).verdict == "legitimate"


def test_save_load(tmp_path, model):
    model.save(tmp_path / "m.joblib")
    m2 = PhishGuard.load(tmp_path / "m.joblib")
    assert m2.check("https://github.com").probability == model.check("https://github.com").probability


def test_cli_check(capsys):
    main(["check", "https://github.com/explore", "http://paypal.com@x.top/login"])
    out = capsys.readouterr().out
    assert "[OK]" in out and ("[PHISHING]" in out or "[SUSPICIOUS]" in out)


def test_api():
    from phishguard.api import app

    c = TestClient(app)
    assert c.get("/health").status_code == 200
    r = c.post("/check", json={"url": "http://192.168.1.20/paypal/login.php"}).json()
    assert r["verdict"] != "legitimate"
    assert c.post("/check", json={"url": ""}).status_code == 422
    assert len(c.post("/check/batch", json=["https://python.org", "https://bit.ly/abc"]).json()) == 2
