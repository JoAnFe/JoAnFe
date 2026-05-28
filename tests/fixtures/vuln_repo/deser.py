"""Intentionally vulnerable sample: insecure deserialization (CWE-502)."""

import pickle


def load_state(network_bytes):
    # Deserializing untrusted bytes enables arbitrary code execution.
    return pickle.loads(network_bytes)
