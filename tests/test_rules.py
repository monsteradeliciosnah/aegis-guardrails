from aegis.dsl import apply_rules, default_rules


def test_redact_email():
    res = apply_rules("Contact me at a@b.com", default_rules())
    assert "[REDACTED]" in res["text"] and res["ok"]
