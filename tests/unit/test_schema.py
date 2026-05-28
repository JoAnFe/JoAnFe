from joanfe.config import ScanConfig
from joanfe.schema.finding import (
    Confidence,
    EvidenceCitation,
    Finding,
)
from pathlib import Path


def _finding(**kw) -> Finding:
    base = dict(
        title="t", cwe_id="CWE-89", cwe_name="SQLi",
        weakness_mechanism="m", exploit_primitive="p", adversary_behaviour="b",
    )
    base.update(kw)
    return Finding(**base)


def test_evidence_gate_requires_precondition_reachability_and_citation():
    f = _finding()
    assert not f.has_sufficient_evidence()

    f.exploit_preconditions = ["x"]
    assert not f.has_sufficient_evidence()

    f.reachability_rationale = "src -> sink"
    assert not f.has_sufficient_evidence()

    f.evidence = [EvidenceCitation(file_path="a.py", start_line=1, end_line=1,
                                   snippet="x", rationale="r")]
    assert f.has_sufficient_evidence()


def test_confidence_threshold():
    cfg = ScanConfig(target=Path("."), min_confidence=Confidence.MEDIUM)
    assert cfg.confidence_meets_threshold(Confidence.HIGH)
    assert cfg.confidence_meets_threshold(Confidence.MEDIUM)
    assert not cfg.confidence_meets_threshold(Confidence.LOW)
