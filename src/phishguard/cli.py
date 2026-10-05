"""phishguard command line."""
from __future__ import annotations

import argparse
import json
import os
import sys

from .model import PhishGuard, default_model, evaluate

ICON = {"phishing": "[PHISHING]", "suspicious": "[SUSPICIOUS]", "legitimate": "[OK]"}


def _model(path: str | None) -> PhishGuard:
    if path and os.path.exists(path):
        return PhishGuard.load(path)
    return default_model()


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="phishguard", description="Phishing URL detector")
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("check", help="classify one or more URLs (or '-' to read stdin)")
    c.add_argument("urls", nargs="+")
    c.add_argument("-m", "--model")
    c.add_argument("--json", action="store_true")

    t = sub.add_parser("train", help="train on the synthetic corpus and save the model")
    t.add_argument("-o", "--output", default="phishguard.joblib")
    t.add_argument("-n", type=int, default=20_000)

    e = sub.add_parser("evaluate", help="hold-out metrics + permutation feature importance")
    e.add_argument("-n", type=int, default=20_000)

    s = sub.add_parser("serve", help="start the REST API")
    s.add_argument("--port", type=int, default=8000)

    a = p.parse_args(argv)

    if a.cmd == "check":
        model = _model(a.model)
        urls = sys.stdin.read().split() if a.urls == ["-"] else a.urls
        for url in urls:
            r = model.check(url)
            if a.json:
                print(json.dumps(r.as_dict()))
            else:
                print(f"{ICON[r.verdict]:<13} {r.probability:6.1%}  {url}")
                for reason in r.reasons:
                    print(f"{'':>21}- {reason}")
    elif a.cmd == "train":
        from .dataset import generate

        urls, labels = generate(a.n)
        PhishGuard().fit(urls, labels).save(a.output)
        print(f"saved model trained on {a.n} URLs -> {a.output}")
    elif a.cmd == "evaluate":
        r = evaluate(a.n)
        for k in ("accuracy", "precision", "recall", "f1", "roc_auc"):
            print(f"{k:<10} {r[k]:.4f}")
        print("\nmost important features (F1 drop when shuffled):")
        for name, drop in r["top_features"]:
            print(f"  {name:<28} {drop:.4f}")
    elif a.cmd == "serve":
        import uvicorn

        uvicorn.run("phishguard.api:app", host="127.0.0.1", port=a.port)


if __name__ == "__main__":
    main()
