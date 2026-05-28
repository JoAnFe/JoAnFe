"""Async Anthropic client wrapper: structured parsing, caching, usage.

All API access funnels through :class:`LLMClient`. Tests inject a fake client
exposing the same ``messages.parse`` surface, so the pipeline never touches the
network in unit/integration tests.
"""

from __future__ import annotations

import logging
from typing import Any, TypeVar

from pydantic import BaseModel

from ..usage import UsageTracker

logger = logging.getLogger("joanfe.llm")

T = TypeVar("T", bound=BaseModel)


class LLMClient:
    """Thin wrapper over ``AsyncAnthropic`` for cached, structured calls."""

    def __init__(
        self,
        client: object | None = None,
        *,
        usage: UsageTracker | None = None,
        verbose: bool = False,
    ) -> None:
        if client is None:
            # Imported lazily so tests (and --dry-run) need no API key/SDK call.
            from anthropic import AsyncAnthropic

            client = AsyncAnthropic()
        self._client: Any = client
        self.usage = usage or UsageTracker()
        self.verbose = verbose

    async def parse(
        self,
        *,
        stage: str,
        model: str,
        system: str,
        user_content: str,
        output_format: type[T],
        max_tokens: int = 8000,
        use_thinking: bool = False,
    ) -> T:
        """One structured call; returns the parsed pydantic model.

        The frozen ``system`` prompt is sent as a single cached text block so
        repeated per-file/per-candidate calls within a stage reuse the prefix.
        """
        kwargs: dict[str, object] = {
            "model": model,
            "max_tokens": max_tokens,
            "system": [
                {
                    "type": "text",
                    "text": system,
                    "cache_control": {"type": "ephemeral"},
                }
            ],
            "messages": [{"role": "user", "content": user_content}],
            "output_format": output_format,
        }
        if use_thinking:
            # Adaptive thinking is off unless explicitly requested on 4.7/4.8.
            kwargs["thinking"] = {"type": "adaptive"}

        response = await self._client.messages.parse(**kwargs)

        usage = getattr(response, "usage", None)
        if usage is not None:
            self.usage.add(stage, model, usage)
            if self.verbose:
                logger.info(
                    "stage=%s model=%s in=%s out=%s cache_read=%s",
                    stage,
                    model,
                    getattr(usage, "input_tokens", "?"),
                    getattr(usage, "output_tokens", "?"),
                    getattr(usage, "cache_read_input_tokens", "?"),
                )

        parsed = getattr(response, "parsed_output", None)
        if parsed is None:
            raise ValueError(f"{stage}: model returned no parseable output")
        return parsed
