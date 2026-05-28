"""Split large files into line-anchored, overlapping windows.

Citations must keep absolute line numbers, so each chunk records the 1-based
line offset of its first line. We estimate tokens cheaply (~4 chars/token) to
decide when a file exceeds the per-call budget.
"""

from __future__ import annotations

from dataclasses import dataclass

from .walker import SourceFile

_CHARS_PER_TOKEN = 4


@dataclass
class Chunk:
    """A contiguous window of a source file with absolute line numbers."""

    rel_path: str
    start_line: int  # 1-based, inclusive
    end_line: int  # 1-based, inclusive
    text: str

    def numbered_text(self) -> str:
        """The chunk text prefixed with absolute line numbers, for prompts."""
        lines = self.text.splitlines()
        return "\n".join(
            f"{self.start_line + i:>6}\t{line}" for i, line in enumerate(lines)
        )


def estimate_tokens(text: str) -> int:
    """Rough token estimate without an API call."""
    return max(1, len(text) // _CHARS_PER_TOKEN)


def chunk_file(
    source: SourceFile, token_budget: int, overlap_lines: int
) -> list[Chunk]:
    """Return one chunk per file, or several overlapping windows if too large."""
    if estimate_tokens(source.text) <= token_budget:
        return [
            Chunk(
                rel_path=source.rel_path,
                start_line=1,
                end_line=source.line_count,
                text=source.text,
            )
        ]

    lines = source.text.splitlines()
    # Convert the token budget into an approximate line window.
    avg_line_chars = max(1, (len(source.text) // max(1, len(lines))))
    lines_per_chunk = max(50, (token_budget * _CHARS_PER_TOKEN) // avg_line_chars)
    step = max(1, lines_per_chunk - overlap_lines)

    chunks: list[Chunk] = []
    start = 0
    while start < len(lines):
        end = min(start + lines_per_chunk, len(lines))
        window = lines[start:end]
        chunks.append(
            Chunk(
                rel_path=source.rel_path,
                start_line=start + 1,
                end_line=end,
                text="\n".join(window),
            )
        )
        if end >= len(lines):
            break
        start += step
    return chunks
