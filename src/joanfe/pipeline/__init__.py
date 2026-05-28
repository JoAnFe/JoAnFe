"""Multi-stage agentic pipeline: triage -> discovery -> validation -> critic
-> dedupe -> synthesis."""

from .orchestrator import Orchestrator

__all__ = ["Orchestrator"]
