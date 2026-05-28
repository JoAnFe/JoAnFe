from joanfe.reporting import render_markdown
from joanfe.schema.finding import (
    AttackMapping,
    Confidence,
    EvidenceCitation,
    Finding,
    Severity,
)
from joanfe.schema.report import ScanResult


def _result() -> ScanResult:
    finding = Finding(
        finding_id="JF-001",
        title="SQL Injection in sqli.py",
        cwe_id="CWE-89",
        cwe_name="SQL Injection",
        weakness_mechanism="Concatenated query.",
        exploit_preconditions=["reachable endpoint"],
        exploit_primitive="query manipulation",
        exploit_outcomes=["credential dump"],
        adversary_behaviour="dumps the users table",
        attack_mappings=[
            AttackMapping(tactic="Collection", technique_id="T1213",
                          technique_name="Data from Repositories",
                          mapping_justification="primitive enables collection")
        ],
        reachability_rationale="param -> execute",
        confidence=Confidence.HIGH,
        severity=Severity.HIGH,
        evidence=[EvidenceCitation(file_path="sqli.py", start_line=5, end_line=5,
                                   snippet="cursor.execute(...)", rationale="sink")],
        risk_narrative="DB compromise.",
        recommendation="Use parameterized queries.",
    )
    appendix = Finding(
        finding_id="JF-APX-001", title="weak", cwe_id="CWE-000", cwe_name="x",
        weakness_mechanism="m", exploit_primitive="p", adversary_behaviour="b",
        confidence=Confidence.LOW, rejection_reason="insufficient evidence",
    )
    return ScanResult(
        target="tests/fixtures/vuln_repo",
        files_scanned=7, files_considered=7,
        executive_summary="One high-severity SQLi found.",
        accepted=[finding], appendix=[appendix],
        model_summary={"validation": "claude-opus-4-8"},
        usage_summary="API calls: 12",
    )


def test_report_contains_all_major_sections():
    md = render_markdown(_result())
    for heading in [
        "# Security Scan Report",
        "## Executive Summary",
        "## Severity x Confidence",
        "## MITRE ATT&CK Coverage",
        "## Findings",
        "## Appendix: Rejected / Low-Confidence Findings",
        "## Scan Metadata",
    ]:
        assert heading in md


def test_finding_renders_methodology_chain_and_evidence():
    md = render_markdown(_result())
    assert "JF-001: SQL Injection in sqli.py" in md
    assert "CWE-89 SQL Injection" in md
    assert "T1213 Data from Repositories" in md
    assert "`sqli.py:5-5`" in md
    assert "cursor.execute(...)" in md
    assert "Use parameterized queries." in md


def test_appendix_lists_rejected_finding():
    md = render_markdown(_result())
    assert "JF-APX-001" in md
    assert "insufficient evidence" in md
