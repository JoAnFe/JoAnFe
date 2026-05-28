"""Intentionally vulnerable sample: path traversal (CWE-22)."""

import os


def read_doc(filename):
    # User-controlled filename joined onto a base path without validation.
    path = os.path.join("/var/www/docs", filename)
    with open(path) as handle:
        return handle.read()
