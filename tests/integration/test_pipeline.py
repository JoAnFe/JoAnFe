"""End-to-end pipeline test with the scripted fake — zero API calls."""

from __future__ import annotations

import pytest

from joanfe.config import ScanConfig
from joanfe.pipeline import Orchestrator
from joanfe.reporting import render_markdown
from joanfe.schema.finding import Confidence

from ..conftest import FIXTURE_REPO, VULN_REGISTRY


@pytest.fixture
def config() -> ScanConfig:
    return ScanConfig(
        target=FIXTURE_REPO,
        max_files=20,
        min_confidence=Confidence.MEDIUM,
        concurrency=4,
        max_critic_iterations=1,
    )


async def test_all_seeded_vulns_detected_with_full_chain(config, fake_llm):
    result = await Orchestrator(config, fake_llm).run()

    detected_cwes = {f.cwe_id for f in result.accepted}
    expected_cwes = {spec.cwe_id for spec in VULN_REGISTRY.values()}
    assert expected_cwes <= detected_cwes

    for finding in result.accepted:
        assert finding.finding_id.startswith("JF-")
        assert finding.evidence, f"{finding.title} has no citations"
        assert finding.attack_mappings, f"{finding.title} has no ATT&CK mapping"
        assert finding.exploit_primitive
        assert finding.has_sufficient_evidence()


async def test_evidence_less_candidate_routed_to_appendix(config, fake_llm):
    result = await Orchestrator(config, fake_llm).run()
    appendix_titles = " ".join(f.title for f in result.appendix)
    assert "Unsubstantiated" in appendix_titles or "notes" in appendix_titles.lower()
    # The benign file must NOT appear among accepted findings.
    assert all("notes.py" not in (c.file_path for c in f.evidence)
               for f in result.accepted)


async def test_citations_verify_against_real_source(config, fake_llm):
    result = await Orchestrator(config, fake_llm).run()
    for finding in result.accepted:
        for cite in finding.evidence:
            src = (FIXTURE_REPO / cite.file_path).read_text().splitlines()
            region = "\n".join(src[cite.start_line - 1 : cite.end_line])
            normalized = " ".join(cite.snippet.split())
            assert normalized in " ".join(region.split())


async def test_report_renders_end_to_end(config, fake_llm):
    result = await Orchestrator(config, fake_llm).run()
    md = render_markdown(result)
    assert "# Security Scan Report" in md
    assert "MITRE ATT&CK Coverage" in md
    assert result.executive_summary
