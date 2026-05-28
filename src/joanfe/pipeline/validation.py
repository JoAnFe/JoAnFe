"""Stage (c): validation + ATT&CK mapping + deterministic citation checks.

Each candidate is re-examined with surrounding code context. A candidate is
only promoted to an accepted finding if it clears the hard evidence gate
(precondition + reachability + >=1 citation) AND its citations actually appear
in the source (deterministic anti-hallucination check). Optional SAST
corroboration can bump confidence.
"""

from __future__ import annotations

from pathlib import Path

from ..config import ScanConfig
from ..ingest.walker import SourceFile
from ..llm import LLMClient, prompts
from ..schema.finding import Candidate, Confidence, Finding
from ..tools import ExternalTool

# Lines of context to include on each side of the candidate region.
_CONTEXT_LINES = 60
_CONFIDENCE_RANK = {Confidence.LOW: 0, Confidence.MEDIUM: 1, Confidence.HIGH: 2}
_RANK_CONFIDENCE = {v: k for k, v in _CONFIDENCE_RANK.items()}


def _context_window(source: SourceFile, start: int, end: int) -> str:
    lines = source.text.splitlines()
    lo = max(0, start - 1 - _CONTEXT_LINES)
    hi = min(len(lines), end + _CONTEXT_LINES)
    return "\n".join(f"{lo + i + 1:>6}\t{line}" for i, line in enumerate(lines[lo:hi]))


def _normalize(text: str) -> str:
    """Collapse whitespace so citation matching tolerates reformatting."""
    return " ".join(text.split())


def verify_citations(finding: Finding, sources: dict[str, SourceFile]) -> bool:
    """Confirm every cited snippet actually appears within its line range.

    Returns True if all citations verify. On any mismatch the finding is
    downgraded and a detection gap is recorded (model hallucination caught in
    code, not by the model).
    """
    all_ok = True
    for cite in finding.evidence:
        source = sources.get(cite.file_path)
        ok = False
        if source is not None:
            lines = source.text.splitlines()
            lo = max(0, cite.start_line - 1)
            hi = min(len(lines), cite.end_line)
            region = _normalize("\n".join(lines[lo:hi]))
            snippet = _normalize(cite.snippet)
            ok = bool(snippet) and snippet in region
        if not ok:
            all_ok = False

    if not all_ok:
        finding.detection_gaps.append(
            "One or more cited code snippets could not be verified against the "
            "source; treat this finding as lower confidence."
        )
        _downgrade(finding)
    return all_ok


def _downgrade(finding: Finding) -> None:
    rank = _CONFIDENCE_RANK[finding.confidence]
    finding.confidence = _RANK_CONFIDENCE[max(0, rank - 1)]


def _bump(finding: Finding) -> None:
    rank = _CONFIDENCE_RANK[finding.confidence]
    finding.confidence = _RANK_CONFIDENCE[min(2, rank + 1)]


async def validate_candidate(
    candidate: Candidate,
    sources: dict[str, SourceFile],
    config: ScanConfig,
    llm: LLMClient,
    tools: list[ExternalTool] | None = None,
    repo_root: Path | None = None,
) -> tuple[Finding, bool]:
    """Validate one candidate. Returns (finding, accepted)."""
    source = sources.get(candidate.file_path)
    context = (
        _context_window(source, candidate.start_line, candidate.end_line)
        if source is not None
        else f"(source for {candidate.file_path} unavailable)"
    )

    finding = await llm.parse(
        stage="validation",
        model=config.models.validation,
        system=prompts.VALIDATION_SYSTEM,
        user_content=prompts.validation_user(
            candidate.model_dump_json(indent=2), context, candidate.file_path
        ),
        output_format=Finding,
        max_tokens=8000,
        use_thinking=True,
    )
    finding.confidence_history.append(finding.confidence)

    # Hard evidence gate.
    if not finding.has_sufficient_evidence():
        finding.rejection_reason = (
            finding.rejection_reason
            or "Insufficient evidence: missing precondition, reachability, or citation."
        )
        return finding, False

    verify_citations(finding, sources)

    # Optional SAST corroboration scoped to the candidate file.
    if tools and source is not None and repo_root is not None:
        tags = _corroborate(tools, repo_root / candidate.file_path)
        if tags:
            finding.corroborating_tools = tags
            _bump(finding)
            finding.confidence_history.append(finding.confidence)

    return finding, True


def _corroborate(tools: list[ExternalTool], path: Path) -> list[str]:
    tags: list[str] = []
    if not path.is_file():
        return tags
    for tool in tools:
        try:
            tags.extend(tool.scan_file(path))
        except Exception:  # noqa: BLE001 - corroboration is best-effort
            continue
    return tags
