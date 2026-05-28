from joanfe.ingest.chunker import chunk_file, estimate_tokens
from joanfe.ingest.walker import SourceFile


def _src(text: str) -> SourceFile:
    return SourceFile(path=None, rel_path="big.py", text=text,  # type: ignore[arg-type]
                      line_count=text.count("\n") + 1)


def test_small_file_is_single_chunk_with_full_range():
    text = "line1\nline2\nline3"
    chunks = chunk_file(_src(text), token_budget=1000, overlap_lines=5)
    assert len(chunks) == 1
    assert chunks[0].start_line == 1
    assert chunks[0].end_line == 3


def test_large_file_is_split_with_overlap_and_absolute_lines():
    text = "\n".join(f"row {i}" for i in range(2000))
    chunks = chunk_file(_src(text), token_budget=200, overlap_lines=20)
    assert len(chunks) > 1
    # Absolute line anchoring: first chunk starts at 1, last ends at the EOF line.
    assert chunks[0].start_line == 1
    assert chunks[-1].end_line == 2000
    # Overlap: each chunk starts before the previous one ended.
    for prev, nxt in zip(chunks, chunks[1:]):
        assert nxt.start_line <= prev.end_line


def test_numbered_text_uses_absolute_line_numbers():
    text = "\n".join(f"row {i}" for i in range(300))
    chunks = chunk_file(_src(text), token_budget=100, overlap_lines=10)
    second = chunks[1]
    first_rendered_line = second.numbered_text().splitlines()[0]
    assert first_rendered_line.lstrip().startswith(str(second.start_line))


def test_estimate_tokens_monotonic():
    assert estimate_tokens("a" * 400) > estimate_tokens("a" * 40)
