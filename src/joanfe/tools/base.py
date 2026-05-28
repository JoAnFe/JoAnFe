"""External SAST tool protocol + availability detection.

Each tool runs scoped to a single candidate file and reports whether it
corroborates a weakness there. Corroboration can bump a finding's confidence;
absence never auto-rejects (consistent with the LLM-first design).
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Protocol


class ExternalTool(Protocol):
    """A targeted, file-scoped SAST corroboration runner."""

    name: str
    binary: str

    def is_available(self) -> bool: ...

    def scan_file(self, path: Path) -> list[str]:
        """Return short corroboration tags (e.g. rule ids) for ``path``."""
        ...


class _SubprocessTool:
    """Shared plumbing for binary-backed tools."""

    name = ""
    binary = ""
    timeout = 60

    def is_available(self) -> bool:
        return shutil.which(self.binary) is not None

    def _run(self, args: list[str]) -> tuple[int, str]:
        try:
            proc = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
            return proc.returncode, proc.stdout
        except (OSError, subprocess.SubprocessError):
            return -1, ""


class SemgrepTool(_SubprocessTool):
    name = "semgrep"
    binary = "semgrep"

    def scan_file(self, path: Path) -> list[str]:
        code, out = self._run(
            ["semgrep", "--config", "auto", "--json", "--quiet", str(path)]
        )
        if code < 0 or not out:
            return []
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            return []
        return [
            f"semgrep:{r.get('check_id', 'rule')}"
            for r in data.get("results", [])
        ]


class BanditTool(_SubprocessTool):
    name = "bandit"
    binary = "bandit"

    def scan_file(self, path: Path) -> list[str]:
        if path.suffix.lower() not in {".py", ".pyi"}:
            return []
        code, out = self._run(["bandit", "-f", "json", "-q", str(path)])
        if not out:
            return []
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            return []
        return [
            f"bandit:{r.get('test_id', 'B000')}" for r in data.get("results", [])
        ]


class GitleaksTool(_SubprocessTool):
    name = "gitleaks"
    binary = "gitleaks"

    def scan_file(self, path: Path) -> list[str]:
        code, out = self._run(
            ["gitleaks", "detect", "--no-git", "--report-format", "json",
             "--report-path", "/dev/stdout", "--source", str(path)]
        )
        if not out:
            return []
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            return []
        if not isinstance(data, list):
            return []
        return [f"gitleaks:{f.get('RuleID', 'secret')}" for f in data]


_ALL_TOOLS: list[_SubprocessTool] = [SemgrepTool(), BanditTool(), GitleaksTool()]


def available_tools() -> list[ExternalTool]:
    """Return the SAST tools whose binaries are present on PATH."""
    return [t for t in _ALL_TOOLS if t.is_available()]  # type: ignore[misc]
