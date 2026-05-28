"""Stage (d): adversarial critic loop.

A skeptic persona tries to refute each finding. The loop is bounded and stops
when the verdict stabilizes, confidence bottoms out on a rejection, or the
iteration cap is hit. Confidence evolves through ``confidence_history``.
"""

from __future__ import annotations

from ..config import ScanConfig
from ..llm import LLMClient, prompts
from ..schema.finding import Confidence, CriticVerdict, Finding


def _cited_code(finding: Finding) -> str:
    blocks = []
    for cite in finding.evidence:
        blocks.append(
            f"# {cite.file_path}:{cite.start_line}-{cite.end_line}\n{cite.snippet}"
        )
    return "\n\n".join(blocks) if blocks else "(no citations provided)"


async def review_finding(
    finding: Finding,
    config: ScanConfig,
    llm: LLMClient,
) -> Finding:
    """Run the bounded adversarial review loop over a single finding."""
    current = finding
    last_verdict: CriticVerdict | None = None
    last_confidence: Confidence | None = None

    for _ in range(config.max_critic_iterations):
        reviewed = await llm.parse(
            stage="critic",
            model=config.models.critic,
            system=prompts.CRITIC_SYSTEM,
            user_content=prompts.critic_user(
                current.model_dump_json(indent=2), _cited_code(current)
            ),
            output_format=Finding,
            max_tokens=6000,
            use_thinking=True,
        )
        # The critic may only adjust verdict/confidence/severity; keep provenance.
        reviewed.confidence_history = [*current.confidence_history, reviewed.confidence]
        reviewed.corroborating_tools = current.corroborating_tools
        current = reviewed

        # Stopping criteria.
        if (
            current.critic_verdict == last_verdict
            and current.confidence == last_confidence
        ):
            break  # stable two rounds in a row
        if (
            current.critic_verdict == CriticVerdict.REJECTED
            and current.confidence == Confidence.LOW
        ):
            break  # rejected and bottomed out
        last_verdict = current.critic_verdict
        last_confidence = current.confidence

    return current
