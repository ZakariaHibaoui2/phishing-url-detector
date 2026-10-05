"""REST API for URL checks."""
from __future__ import annotations

import os

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from . import __version__
from .model import PhishGuard, default_model

app = FastAPI(title="PhishGuard", version=__version__, description="Phishing URL detection API")
_path = os.environ.get("PHISHGUARD_MODEL")
MODEL = PhishGuard.load(_path) if _path and os.path.exists(_path) else default_model()


class UrlIn(BaseModel):
    url: str = Field(min_length=3, max_length=4096)


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "version": __version__}


@app.post("/check")
def check(body: UrlIn) -> dict:
    return MODEL.check(body.url).as_dict()


@app.post("/check/batch")
def check_batch(urls: list[str]) -> list[dict]:
    if not 0 < len(urls) <= 1000:
        raise HTTPException(400, "send between 1 and 1000 URLs")
    return [MODEL.check(u).as_dict() for u in urls]
