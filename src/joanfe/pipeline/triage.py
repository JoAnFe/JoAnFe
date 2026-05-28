"""Stage (a): triage/scoping.

Heuristic scoring always runs (token-free). When an LLM client is supplied, a
single cheap batched Haiku call re-ranks the top heuristic candidates. The
output is an ordered, capped list of files to analyze.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from ..config import ScanConfig
from ..ingest import ScoredFile, score_files
from ..ingest.walker import SourceFile
from ..llm import LLMClient
from ..llm import prompts


class FileTriage(BaseModel):
    file_path: str
    likelihood: int = Field(description="0-100 likelihood of a real weakness.")
    category: str = ""


class TriageBatch(BaseModel):
    files: list[FileTriage] = Field(default_factory=list)


def _summarize(scored: ScoredFile) -> str:
    sf = scored.source
    head = "\n".join(sf.text.splitlines()[:4])
    tags = ", ".join(scored.categories) or "none"
    return (
        f"- path: {sf.rel_path}\n"
        f"  heuristic_score: {scored.score}\n"
        f"  tags: {tags}\n"
        f"  lines: {sf.line_count}\n"
        f"  head: {head[:200]!r}"
    )


async def triage(
    files: list[SourceFile],
    config: ScanConfig,
    llm: LLMClient | None,
) -> list[ScoredFile]:
    """Return files ranked by likelihood of containing a real weakness."""
    scored = score_files(files)

    # Cap the candidate set to the most promising files before LLM refinement.
    top = scored[: max(config.max_files * 2, config.max_files)]

    if llm is None or not top:
        return scored[: config.max_files]

    summaries = "\n".join(_summarize(s) for s in top)
    try:
        batch = await llm.parse(
            stage="triage",
            model=config.models.triage,
            system=prompts.TRIAGE_SYSTEM,
            user_content=prompts.triage_user(summaries),
            output_format=TriageBatch,
            max_tokens=4000,
        )
    except Exception:  # noqa: BLE001 - triage is best-effort; fall back to heuristic
        return scored[: config.max_files]

    llm_rank = {f.file_path: f.likelihood for f in batch.files}
    # Blend: LLM likelihood dominates, heuristic breaks ties.
    top.sort(
        key=lambda s: (-(llm_rank.get(s.source.rel_path, 0)), -s.score, s.source.rel_path)
    )
    return top[: config.max_files]
