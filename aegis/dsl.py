from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List

import regex as re


@dataclass
class Rule:
    name: str
    pattern: str
    message: str
    action: str = "block"  # block | redact | allow


PII_PATTERNS = {
    "email": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
    "phone": r"(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4})",
    "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
}


def apply_rules(text: str, rules: List[Rule]) -> Dict:
    violations = []
    redacted = text
    for r in rules:
        for m in re.finditer(r.pattern, text, flags=re.IGNORECASE):
            violations.append(
                {
                    "rule": r.name,
                    "span": [m.start(), m.end()],
                    "match": m.group(0),
                    "message": r.message,
                    "action": r.action,
                }
            )
            if r.action == "redact":
                redacted = redacted.replace(m.group(0), "[REDACTED]")
            if r.action == "block":
                # keep redacted as-is; caller can decide
                pass
    return {
        "ok": not any(v["action"] == "block" for v in violations),
        "text": redacted,
        "violations": violations,
    }


def default_rules() -> List[Rule]:
    return [
        Rule("pii_email", PII_PATTERNS["email"], "Email detected", action="redact"),
        Rule("pii_phone", PII_PATTERNS["phone"], "Phone detected", action="redact"),
        Rule("pii_ssn", PII_PATTERNS["ssn"], "SSN detected", action="block"),
        Rule(
            "prompt_injection",
            r"(?s)ignore previous|override instructions|system prompt",
            "Prompt-injection cue",
            action="block",
        ),
    ]
