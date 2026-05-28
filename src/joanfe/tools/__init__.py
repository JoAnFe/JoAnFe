"""Optional external SAST corroboration.

LLM-first: these tools are never required. If the binary is missing or fails,
corroboration is simply absent — it never blocks or rejects a finding.
"""

from .base import ExternalTool, available_tools

__all__ = ["ExternalTool", "available_tools"]
