from joanfe.ingest.walker import SourceFile
from joanfe.pipeline.validation import verify_citations
from joanfe.schema.finding import Confidence, EvidenceCitation, Finding


def _source() -> dict[str, SourceFile]:
    text = "import os\ndef ping(host):\n    os.system('ping ' + host)\n"
    return {
        "cmd.py": SourceFile(path=None, rel_path="cmd.py", text=text,  # type: ignore[arg-type]
                             line_count=3)
    }


def _finding(snippet: str, start: int, end: int) -> Finding:
    return Finding(
        title="t", cwe_id="CWE-78", cwe_name="cmd", weakness_mechanism="m",
        exploit_primitive="rce", adversary_behaviour="b",
        confidence=Confidence.HIGH,
        evidence=[EvidenceCitation(file_path="cmd.py", start_line=start,
                                   end_line=end, snippet=snippet, rationale="r")],
    )


def test_verified_citation_keeps_confidence():
    f = _finding("os.system('ping ' + host)", 3, 3)
    assert verify_citations(f, _source())
    assert f.confidence == Confidence.HIGH


def test_hallucinated_citation_is_downgraded_and_flagged():
    f = _finding("eval(totally_made_up_variable)", 3, 3)
    assert not verify_citations(f, _source())
    assert f.confidence == Confidence.MEDIUM  # downgraded one level
    assert any("could not be verified" in gap for gap in f.detection_gaps)


def test_whitespace_normalized_match():
    # Leading/trailing indentation differences must be tolerated.
    f = _finding("    os.system('ping ' + host)\n", 3, 3)
    assert verify_citations(f, _source())
