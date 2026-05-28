"""Stage (e): deterministic dedupe / clustering of findings.

Cluster findings by (normalized path, overlapping line ranges, CWE). Keep the
highest-confidence representative and union evidence + tool corroboration.
"""

from __future__ import annotations

from ..schema.finding import Confidence, Finding

_CONFIDENCE_RANK = {Confidence.LOW: 0, Confidence.MEDIUM: 1, Confidence.HIGH: 2}


def _line_span(finding: Finding) -> tuple[int, int]:
    if not finding.evidence:
        return (0, 0)
    starts = [c.start_line for c in finding.evidence]
    ends = [c.end_line for c in finding.evidence]
    return (min(starts), max(ends))


def _overlaps(a: tuple[int, int], b: tuple[int, int]) -> bool:
    return a[0] <= b[1] and b[0] <= a[1]


def dedupe(findings: list[Finding]) -> list[Finding]:
    """Merge near-duplicate findings; return one representative per cluster."""
    clusters: list[Finding] = []
    for finding in findings:
        span = _line_span(finding)
        path = finding.evidence[0].file_path if finding.evidence else ""
        merged = False
        for rep in clusters:
            rep_span = _line_span(rep)
            rep_path = rep.evidence[0].file_path if rep.evidence else ""
            if (
                path == rep_path
                and rep.cwe_id == finding.cwe_id
                and _overlaps(span, rep_span)
            ):
                _merge_into(rep, finding)
                merged = True
                break
        if not merged:
            clusters.append(finding)
    return clusters


def _merge_into(rep: Finding, other: Finding) -> None:
    """Fold ``other`` into ``rep``, keeping the stronger of the two."""
    if _CONFIDENCE_RANK[other.confidence] > _CONFIDENCE_RANK[rep.confidence]:
        rep.confidence = other.confidence
        rep.risk_narrative = other.risk_narrative or rep.risk_narrative
    # Union evidence, dedup by (path, start_line).
    seen = {(c.file_path, c.start_line) for c in rep.evidence}
    for cite in other.evidence:
        if (cite.file_path, cite.start_line) not in seen:
            rep.evidence.append(cite)
            seen.add((cite.file_path, cite.start_line))
    rep.corroborating_tools = sorted(
        set(rep.corroborating_tools) | set(other.corroborating_tools)
    )
