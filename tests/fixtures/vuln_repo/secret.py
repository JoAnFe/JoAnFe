"""Intentionally vulnerable sample: hardcoded credentials (CWE-798)."""

# A hardcoded API key committed to source control.
API_KEY = "AKIAIOSFODNN7EXAMPLE"


def client():
    return {"key": API_KEY}
