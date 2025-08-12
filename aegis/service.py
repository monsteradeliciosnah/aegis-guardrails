from __future__ import annotations

from fastapi import FastAPI
from pydantic import BaseModel

from .dsl import apply_rules, default_rules

app = FastAPI(title="Aegis Guardrails")


class CheckRequest(BaseModel):
    text: str


@app.post("/check")
def check(req: CheckRequest):
    res = apply_rules(req.text, default_rules())
    return res
