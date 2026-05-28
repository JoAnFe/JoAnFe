"""Model-ID constants and per-stage model selection.

Model IDs are the exact strings valid for this environment. Cheap models do
triage; stronger models do validation and the adversarial critique.
"""

from __future__ import annotations

from dataclasses import dataclass

# Exact model IDs (do not append date suffixes).
HAIKU = "claude-haiku-4-5"
SONNET = "claude-sonnet-4-6"
OPUS = "claude-opus-4-8"


@dataclass(frozen=True)
class StageModels:
    """Which model each pipeline stage uses by default."""

    triage: str = HAIKU
    discovery: str = SONNET
    validation: str = OPUS
    critic: str = OPUS
    synthesis: str = SONNET
    dedupe: str = SONNET


DEFAULT_STAGE_MODELS = StageModels()
