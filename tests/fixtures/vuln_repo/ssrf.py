"""Intentionally vulnerable sample: SSRF (CWE-918)."""

import requests


def fetch(user_url):
    # User-controlled URL fetched server-side without allowlisting.
    return requests.get(user_url).text
