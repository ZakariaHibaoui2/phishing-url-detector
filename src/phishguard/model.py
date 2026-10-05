"""Gradient-boosted phishing classifier with explanations."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split

from .dataset import generate
from .features import FEATURE_NAMES, extract, reasons, vectorize


@dataclass
class Result:
    url: str
    verdict: str          # "phishing" | "suspicious" | "legitimate"
    probability: float    # P(phishing)
    reasons: list[str]

    def as_dict(self) -> dict:
        return asdict(self)


# High-severity indicators that are almost never legitimate. They set a floor on the score so a
# model blind spot can never let them through (defence in depth: rules + ML).
RULE_FLOORS = {
    "has_at": 0.90,
    "brand_in_subdomain_or_path": 0.80,
    "brand_lookalike": 0.75,
    "punycode": 0.70,
    "is_ip_host": 0.70,
}


def rule_floor(feats: dict[str, float]) -> float:
    return max([v for k, v in RULE_FLOORS.items() if feats.get(k)] or [0.0])


class PhishGuard:
    def __init__(self, threshold: float = 0.5, suspicious_band: float = 0.2, seed: int = 0):
        self.clf = HistGradientBoostingClassifier(max_iter=300, learning_rate=0.08, random_state=seed)
        self.threshold = threshold
        self.band = suspicious_band
        self.fitted = False

    def fit(self, urls: list[str], labels: list[int]) -> PhishGuard:
        self.clf.fit(np.asarray(vectorize(urls)), np.asarray(labels))
        self.fitted = True
        return self

    def proba(self, urls: list[str]) -> np.ndarray:
        if not self.fitted:
            raise RuntimeError("model is not trained")
        ml = self.clf.predict_proba(np.asarray(vectorize(urls)))[:, 1]
        floors = np.asarray([rule_floor(extract(u)) for u in urls])
        return np.maximum(ml, floors)

    def check(self, url: str) -> Result:
        p = float(self.proba([url])[0])
        if p >= self.threshold:
            verdict = "phishing"
        elif p >= self.threshold - self.band:
            verdict = "suspicious"
        else:
            verdict = "legitimate"
        feats = extract(url)
        why = reasons(feats) if verdict != "legitimate" else []
        if verdict == "phishing" and feats["shortener"] and not set(why) - {
            "URL shortener hides the destination", "not using HTTPS"
        }:
            verdict = "suspicious"  # unknown destination, not proof of phishing: expand it before deciding
        return Result(url, verdict, round(p, 4), why)

    def save(self, path: str | Path) -> None:
        joblib.dump(self, path)

    @staticmethod
    def load(path: str | Path) -> PhishGuard:
        m = joblib.load(path)
        if not isinstance(m, PhishGuard):
            raise TypeError("not a PhishGuard model")
        return m


def evaluate(n: int = 20_000, seed: int = 11) -> dict:
    urls, labels = generate(n, seed=seed)
    u_tr, u_te, y_tr, y_te = train_test_split(urls, labels, test_size=0.25, stratify=labels, random_state=seed)
    model = PhishGuard().fit(u_tr, y_tr)
    p = model.proba(u_te)
    pred = (p >= model.threshold).astype(int)
    perm = _permutation_importance(model, u_te, np.asarray(y_te))
    return {
        "model": model,
        "accuracy": accuracy_score(y_te, pred),
        "precision": precision_score(y_te, pred),
        "recall": recall_score(y_te, pred),
        "f1": f1_score(y_te, pred),
        "roc_auc": roc_auc_score(y_te, p),
        "top_features": perm[:8],
    }


def _permutation_importance(model: PhishGuard, urls: list[str], y: np.ndarray, seed: int = 0):
    x = np.asarray(vectorize(urls))
    base = f1_score(y, (model.clf.predict_proba(x)[:, 1] >= model.threshold).astype(int))  # ML part only
    rng = np.random.default_rng(seed)
    scores = []
    for j, name in enumerate(FEATURE_NAMES):
        xp = x.copy()
        xp[:, j] = rng.permutation(xp[:, j])
        drop = base - f1_score(y, (model.clf.predict_proba(xp)[:, 1] >= model.threshold).astype(int))
        scores.append((name, round(float(drop), 4)))
    return sorted(scores, key=lambda t: -t[1])


def default_model() -> PhishGuard:
    urls, labels = generate(12_000)
    return PhishGuard().fit(urls, labels)
