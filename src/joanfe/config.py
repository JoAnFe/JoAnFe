"""Scan configuration: thresholds, model selection, and ingestion limits."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from pathlib import Path

from .models import DEFAULT_STAGE_MODELS, StageModels
from .schema.finding import Confidence

# Default source extensions considered for scanning.
DEFAULT_SOURCE_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".py", ".pyi", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
        ".java", ".kt", ".scala", ".go", ".rb", ".php", ".cs",
        ".c", ".h", ".cpp", ".hpp", ".cc", ".rs", ".swift",
        ".sh", ".bash", ".sql", ".tf", ".yaml", ".yml",
    }
)

# Directory names always skipped during the walk.
DEFAULT_IGNORE_DIRS: frozenset[str] = frozenset(
    {
        ".git", "node_modules", "vendor", "dist", "build", "target",
        "__pycache__", ".venv", "venv", ".mypy_cache", ".pytest_cache",
        ".tox", ".idea", ".gradle", "site-packages",
    }
)

_CONFIDENCE_RANK = {Confidence.LOW: 0, Confidence.MEDIUM: 1, Confidence.HIGH: 2}


@dataclass
class ScanConfig:
    """All knobs controlling a single scan run."""

    target: Path
    include: tuple[str, ...] = ()
    exclude: tuple[str, ...] = ()
    max_files: int = 40
    min_confidence: Confidence = Confidence.MEDIUM
    output: Path = Path("report.md")
    json_output: Path | None = None
    enable_tools: bool = False
    max_critic_iterations: int = 2
    concurrency: int = 5
    dry_run: bool = False
    verbose: bool = False
    models: StageModels = field(default_factory=lambda: DEFAULT_STAGE_MODELS)

    # Per-file/chunk token budget before chunking kicks in.
    chunk_token_budget: int = 6000
    chunk_overlap_lines: int = 40
    source_extensions: frozenset[str] = DEFAULT_SOURCE_EXTENSIONS
    ignore_dirs: frozenset[str] = DEFAULT_IGNORE_DIRS

    def confidence_meets_threshold(self, confidence: Confidence) -> bool:
        """True when ``confidence`` is at or above the configured minimum."""
        return _CONFIDENCE_RANK[confidence] >= _CONFIDENCE_RANK[self.min_confidence]

    def with_models(self, **overrides: str) -> "ScanConfig":
        """Return a copy with selected per-stage model overrides applied."""
        new_models = replace(self.models, **{k: v for k, v in overrides.items() if v})
        return replace(self, models=new_models)
