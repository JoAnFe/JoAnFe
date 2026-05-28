"""The Finding contract — encodes the full README evidence-led methodology.

Each accepted finding walks the chain:
    CWE -> Exploit Preconditions -> Exploit Primitive -> Exploit Outcomes ->
    Adversary Behaviour -> MITRE ATT&CK -> Confidence ->
    Evidence/Assumptions/Detection Gaps -> Risk Narrative + Recommendation.

The analyst rule is encoded structurally: an ``AttackMapping`` must justify
itself by reference to the exploit primitive/outcome, never CWE -> ATT&CK
directly.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class CriticVerdict(str, Enum):
    CONFIRMED = "confirmed"
    DOWNGRADED = "downgraded"
    REJECTED = "rejected"
    UNREVIEWED = "unreviewed"


class EvidenceCitation(BaseModel):
    """A verbatim code citation backing a finding."""

    file_path: str = Field(description="Repo-relative path to the cited file.")
    start_line: int = Field(description="1-based first line of the cited region.")
    end_line: int = Field(description="1-based last line of the cited region.")
    snippet: str = Field(description="Verbatim code from the cited region.")
    rationale: str = Field(description="Why this code is evidence of the weakness.")


class AttackMapping(BaseModel):
    """A single MITRE ATT&CK technique mapping."""

    tactic: str = Field(description="ATT&CK tactic, e.g. 'Credential Access'.")
    technique_id: str = Field(description="ATT&CK technique ID, e.g. 'T1190'.")
    technique_name: str = Field(description="ATT&CK technique name.")
    mapping_justification: str = Field(
        description=(
            "Why this technique applies, referencing the exploit primitive and "
            "outcome. MUST NOT map the CWE directly to ATT&CK without that context."
        )
    )


class Candidate(BaseModel):
    """A cheap, recall-biased discovery candidate (pre-validation)."""

    title: str
    cwe_id: str = Field(description="Best-guess CWE id, e.g. 'CWE-89'.")
    file_path: str
    start_line: int
    end_line: int
    reason: str = Field(description="One-line reason this looks like a weakness.")
    provisional_confidence: Confidence = Confidence.LOW


class CandidateBatch(BaseModel):
    """Discovery output for one file/chunk."""

    candidates: list[Candidate] = Field(default_factory=list)


class Finding(BaseModel):
    """A validated weakness with the complete methodology chain."""

    finding_id: str = ""
    title: str
    cwe_id: str
    cwe_name: str
    weakness_mechanism: str = Field(description="Plain-language: what is broken.")
    exploit_preconditions: list[str] = Field(
        default_factory=list,
        description="Exposure, authentication, privilege, user-interaction requirements.",
    )
    exploit_primitive: str = Field(description="Capability the attacker gains.")
    exploit_outcomes: list[str] = Field(
        default_factory=list, description="What the attacker can realistically achieve."
    )
    adversary_behaviour: str = Field(
        description="Intrusion-time behaviour bridging the primitive to ATT&CK."
    )
    attack_mappings: list[AttackMapping] = Field(default_factory=list)
    reachability_rationale: str = Field(
        default="", description="Source -> sink data-flow / reachability argument."
    )
    confidence: Confidence = Confidence.LOW
    severity: Severity = Severity.MEDIUM
    evidence: list[EvidenceCitation] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)
    detection_gaps: list[str] = Field(default_factory=list)
    risk_narrative: str = ""
    recommendation: str = ""

    # Pipeline provenance (not authored by the discovery/validation prompt).
    corroborating_tools: list[str] = Field(default_factory=list)
    critic_verdict: CriticVerdict = CriticVerdict.UNREVIEWED
    critic_reasons: list[str] = Field(default_factory=list)
    confidence_history: list[Confidence] = Field(default_factory=list)
    rejection_reason: str = ""

    def has_sufficient_evidence(self) -> bool:
        """Hard evidence gate: precondition + reachability + >=1 citation."""
        return bool(
            self.exploit_preconditions
            and self.reachability_rationale.strip()
            and self.evidence
        )

    def primary_location(self) -> str:
        """A short ``file:line`` label for the first citation, for grouping."""
        if self.evidence:
            cite = self.evidence[0]
            return f"{cite.file_path}:{cite.start_line}"
        return self.cwe_id
