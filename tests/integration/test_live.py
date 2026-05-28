"""Opt-in live test: one real end-to-end pass over the fixture repo.

Skipped unless ``--run-live`` is passed AND an API key is present. Verifies a
report renders, prompt caching engages on later calls, and no SAST binary is
required for success.
"""

from __future__ import annotations

import os

import pytest

from joanfe.config import ScanConfig
from joanfe.llm import LLMClient
from joanfe.pipeline import Orchestrator
from joanfe.reporting import render_markdown
from joanfe.schema.finding import Confidence

from ..conftest import FIXTURE_REPO


@pytest.mark.live
async def test_live_scan_of_fixture_repo():
    if not (os.getenv("ANTHROPIC_API_KEY") or os.getenv("ANTHROPIC_AUTH_TOKEN")):
        pytest.skip("no API key in environment")

    config = ScanConfig(
        target=FIXTURE_REPO,
        max_files=6,
        min_confidence=Confidence.MEDIUM,
        concurrency=3,
        max_critic_iterations=1,
    )
    llm = LLMClient(verbose=True)
    result = await Orchestrator(config, llm).run()

    md = render_markdown(result)
    assert "# Security Scan Report" in md
    # Caching should engage once the frozen system prefix has been written.
    assert llm.usage.cache_hits() > 0
