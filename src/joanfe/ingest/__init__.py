"""Repository ingestion: walking, heuristic prioritization, and chunking.

This package knows nothing about LLMs — it only turns a repo on disk into
ranked, chunked source files ready for analysis.
"""

from .chunker import Chunk, chunk_file
from .prioritizer import RISK_CATEGORIES, ScoredFile, score_files
from .walker import SourceFile, walk_repo

__all__ = [
    "Chunk",
    "RISK_CATEGORIES",
    "ScoredFile",
    "SourceFile",
    "chunk_file",
    "score_files",
    "walk_repo",
]
