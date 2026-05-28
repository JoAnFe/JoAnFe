"""Stage (b): candidate discovery.

Recall-biased pass over each file/chunk. Returns lightweight candidates; no
ATT&CK mapping yet. Runs concurrently across chunks via the orchestrator.
"""

from __future__ import annotations

from ..config import ScanConfig
from ..ingest import ScoredFile
from ..ingest.chunker import chunk_file
from ..llm import LLMClient, prompts
from ..schema.finding import Candidate, CandidateBatch


async def discover_in_file(
    scored: ScoredFile,
    config: ScanConfig,
    llm: LLMClient,
) -> list[Candidate]:
    """Discover candidate weaknesses across all chunks of one file."""
    candidates: list[Candidate] = []
    chunks = chunk_file(
        scored.source, config.chunk_token_budget, config.chunk_overlap_lines
    )
    for chunk in chunks:
        batch = await llm.parse(
            stage="discovery",
            model=config.models.discovery,
            system=prompts.DISCOVERY_SYSTEM,
            user_content=prompts.discovery_user(
                chunk.numbered_text(), chunk.rel_path, scored.categories
            ),
            output_format=CandidateBatch,
            max_tokens=8000,
        )
        for cand in batch.candidates:
            # Force the path to the real file; models occasionally drift.
            cand.file_path = scored.source.rel_path
            candidates.append(cand)
    return _dedupe_candidates(candidates)


def _dedupe_candidates(candidates: list[Candidate]) -> list[Candidate]:
    """Collapse overlapping candidates from chunk overlap regions."""
    seen: dict[tuple[str, str, int], Candidate] = {}
    for cand in candidates:
        key = (cand.file_path, cand.cwe_id, cand.start_line)
        if key not in seen:
            seen[key] = cand
    return list(seen.values())
