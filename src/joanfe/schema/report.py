"""Aggregate scan result assembled by the synthesis stage."""

from __future__ import annotations

from collections import Counter

from pydantic import BaseModel, Field

from .finding import Confidence, Finding, Severity

# Severity ordering for sorting (most severe first).
_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}
_CONFIDENCE_ORDER = {Confidence.HIGH: 0, Confidence.MEDIUM: 1, Confidence.LOW: 2}


class ScanResult(BaseModel):
    """Everything needed to render a report."""

    target: str
    files_scanned: int = 0
    files_considered: int = 0
    executive_summary: str = ""
    accepted: list[Finding] = Field(default_factory=list)
    appendix: list[Finding] = Field(
        default_factory=list,
        description="Rejected / below-threshold findings, kept for transparency.",
    )
    usage_summary: str = ""
    model_summary: dict[str, str] = Field(default_factory=dict)

    def sorted_accepted(self) -> list[Finding]:
        """Accepted findings sorted by severity then confidence."""
        return sorted(
            self.accepted,
            key=lambda f: (
                _SEVERITY_ORDER.get(f.severity, 99),
                _CONFIDENCE_ORDER.get(f.confidence, 99),
            ),
        )

    def severity_confidence_matrix(self) -> dict[tuple[Severity, Confidence], int]:
        """Counts keyed by (severity, confidence) over accepted findings."""
        counter: Counter[tuple[Severity, Confidence]] = Counter()
        for f in self.accepted:
            counter[(f.severity, f.confidence)] += 1
        return dict(counter)

    def attack_coverage(self) -> dict[str, int]:
        """Counts of accepted findings per ATT&CK technique (id + name)."""
        counter: Counter[str] = Counter()
        for f in self.accepted:
            for mapping in f.attack_mappings:
                counter[f"{mapping.technique_id} {mapping.technique_name}"] += 1
        return dict(counter)
