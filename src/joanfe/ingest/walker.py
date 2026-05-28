"""Walk a repository into a filtered list of source files.

Honors ``.gitignore`` (via ``pathspec`` when available), a built-in ignore
list, source-extension filtering, user include/exclude globs, and a binary
sniff so we never feed non-text into the pipeline.
"""

from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass
from pathlib import Path

try:  # pathspec is a declared dependency, but degrade gracefully.
    import pathspec
except ImportError:  # pragma: no cover - exercised only without the dep
    pathspec = None  # type: ignore[assignment]

from ..config import ScanConfig


@dataclass
class SourceFile:
    """One text source file selected for scanning."""

    path: Path  # absolute path on disk
    rel_path: str  # repo-relative, forward-slash normalized
    text: str
    line_count: int


def _load_gitignore(root: Path) -> "pathspec.PathSpec | None":
    if pathspec is None:
        return None
    gitignore = root / ".gitignore"
    if not gitignore.is_file():
        return None
    try:
        lines = gitignore.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return None
    return pathspec.PathSpec.from_lines("gitwildmatch", lines)


def _is_binary(path: Path) -> bool:
    """Cheap binary sniff: a NUL byte in the first 8 KiB means binary."""
    try:
        with path.open("rb") as fh:
            return b"\x00" in fh.read(8192)
    except OSError:
        return True


def _matches_any(rel_path: str, patterns: tuple[str, ...]) -> bool:
    name = os.path.basename(rel_path)
    return any(
        fnmatch.fnmatch(rel_path, pat) or fnmatch.fnmatch(name, pat) for pat in patterns
    )


def walk_repo(config: ScanConfig) -> list[SourceFile]:
    """Return the text source files under ``config.target`` that pass filters."""
    root = config.target.resolve()
    if root.is_file():
        # Allow scanning a single file directly.
        return _read_single(root, root.parent, config)

    spec = _load_gitignore(root)
    results: list[SourceFile] = []

    for dirpath, dirnames, filenames in os.walk(root):
        # Prune ignored directories in place so os.walk doesn't descend.
        dirnames[:] = [d for d in dirnames if d not in config.ignore_dirs]
        for filename in filenames:
            abs_path = Path(dirpath) / filename
            rel_path = abs_path.relative_to(root).as_posix()

            if abs_path.suffix.lower() not in config.source_extensions:
                continue
            if spec is not None and spec.match_file(rel_path):
                continue
            if config.include and not _matches_any(rel_path, config.include):
                continue
            if config.exclude and _matches_any(rel_path, config.exclude):
                continue
            if _is_binary(abs_path):
                continue

            sf = _read_file(abs_path, rel_path)
            if sf is not None:
                results.append(sf)

    results.sort(key=lambda f: f.rel_path)
    return results


def _read_single(path: Path, base: Path, config: ScanConfig) -> list[SourceFile]:
    if path.suffix.lower() not in config.source_extensions or _is_binary(path):
        return []
    sf = _read_file(path, path.relative_to(base).as_posix())
    return [sf] if sf is not None else []


def _read_file(abs_path: Path, rel_path: str) -> SourceFile | None:
    try:
        text = abs_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    return SourceFile(
        path=abs_path,
        rel_path=rel_path,
        text=text,
        line_count=text.count("\n") + 1,
    )
