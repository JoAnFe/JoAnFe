"""Intentionally vulnerable sample: OS command injection (CWE-78)."""

import os


def ping(host):
    # Unsanitized user input flows into a shell command.
    os.system("ping -c 1 " + host)
