"""Token and cost accounting across pipeline stages."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

# USD per 1M tokens (input, output). Cached reads bill ~0.1x input.
_PRICING: dict[str, tuple[float, float]] = {
    "claude-opus-4-8": (5.0, 25.0),
    "claude-sonnet-4-6": (3.0, 15.0),
    "claude-haiku-4-5": (1.0, 5.0),
}


@dataclass
class StageUsage:
    calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_creation_tokens: int = 0


@dataclass
class UsageTracker:
    """Accumulates per-(stage, model) token usage and estimates cost."""

    stages: dict[tuple[str, str], StageUsage] = field(
        default_factory=lambda: defaultdict(StageUsage)
    )

    def add(self, stage: str, model: str, usage: object) -> None:
        """Record one API call's usage. ``usage`` is an Anthropic usage object."""
        entry = self.stages[(stage, model)]
        entry.calls += 1
        entry.input_tokens += int(getattr(usage, "input_tokens", 0) or 0)
        entry.output_tokens += int(getattr(usage, "output_tokens", 0) or 0)
        entry.cache_read_tokens += int(getattr(usage, "cache_read_input_tokens", 0) or 0)
        entry.cache_creation_tokens += int(
            getattr(usage, "cache_creation_input_tokens", 0) or 0
        )

    def total_calls(self) -> int:
        return sum(s.calls for s in self.stages.values())

    def estimated_cost_usd(self) -> float:
        total = 0.0
        for (_stage, model), s in self.stages.items():
            in_price, out_price = _PRICING.get(model, (0.0, 0.0))
            # Cached reads are ~0.1x the input price; cache writes ~1.25x.
            total += (s.input_tokens / 1_000_000) * in_price
            total += (s.cache_read_tokens / 1_000_000) * in_price * 0.1
            total += (s.cache_creation_tokens / 1_000_000) * in_price * 1.25
            total += (s.output_tokens / 1_000_000) * out_price
        return total

    def cache_hits(self) -> int:
        return sum(s.cache_read_tokens for s in self.stages.values())

    def summary(self) -> str:
        """A compact multi-line summary for the report footer."""
        lines = [
            f"API calls: {self.total_calls()} | "
            f"cache-read tokens: {self.cache_hits():,} | "
            f"estimated cost: ${self.estimated_cost_usd():.4f}",
        ]
        for (stage, model), s in sorted(self.stages.items()):
            lines.append(
                f"  - {stage} ({model}): {s.calls} calls, "
                f"in={s.input_tokens:,} out={s.output_tokens:,} "
                f"cache_read={s.cache_read_tokens:,}"
            )
        return "\n".join(lines)
