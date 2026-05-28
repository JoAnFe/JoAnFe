"""LLM access layer: client wrapper and frozen, cacheable prompts.

This package knows nothing about finding semantics beyond the schemas it is
asked to parse into — orchestration lives in ``joanfe.pipeline``.
"""

from .client import LLMClient

__all__ = ["LLMClient"]
