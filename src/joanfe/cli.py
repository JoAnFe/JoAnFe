"""Command-line interface: ``joanfe scan PATH [options]``."""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
from pathlib import Path

from .config import ScanConfig
from .ingest import score_files, walk_repo
from .llm import LLMClient
from .pipeline import Orchestrator
from .reporting import render_markdown
from .schema.finding import Confidence
from .tools import available_tools


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="joanfe",
        description="Agentic static code scanner (CWE -> MITRE ATT&CK, evidence-led).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan a repository for security weaknesses.")
    scan.add_argument("path", type=Path, help="Path to a repo or file to scan.")
    scan.add_argument("--include", action="append", default=[], metavar="GLOB")
    scan.add_argument("--exclude", action="append", default=[], metavar="GLOB")
    scan.add_argument("--max-files", type=int, default=40)
    scan.add_argument(
        "--min-confidence",
        choices=[c.value for c in Confidence],
        default=Confidence.MEDIUM.value,
    )
    scan.add_argument("--output", type=Path, default=Path("report.md"))
    scan.add_argument("--json", dest="json_output", type=Path, default=None)
    scan.add_argument("--enable-tools", action="store_true")
    scan.add_argument("--max-critic-iterations", type=int, default=2)
    scan.add_argument("--concurrency", type=int, default=5)
    scan.add_argument("--triage-model", default=None)
    scan.add_argument("--discovery-model", default=None)
    scan.add_argument("--validation-model", default=None)
    scan.add_argument("--critic-model", default=None)
    scan.add_argument("--synthesis-model", default=None)
    scan.add_argument(
        "--dry-run",
        action="store_true",
        help="Triage + cost estimate only; no validation calls.",
    )
    scan.add_argument("--verbose", action="store_true")
    return parser


def _config_from_args(args: argparse.Namespace) -> ScanConfig:
    config = ScanConfig(
        target=args.path,
        include=tuple(args.include),
        exclude=tuple(args.exclude),
        max_files=args.max_files,
        min_confidence=Confidence(args.min_confidence),
        output=args.output,
        json_output=args.json_output,
        enable_tools=args.enable_tools,
        max_critic_iterations=args.max_critic_iterations,
        concurrency=args.concurrency,
        dry_run=args.dry_run,
        verbose=args.verbose,
    )
    return config.with_models(
        triage=args.triage_model,
        discovery=args.discovery_model,
        validation=args.validation_model,
        critic=args.critic_model,
        synthesis=args.synthesis_model,
    )


def _run_dry(config: ScanConfig) -> int:
    files = walk_repo(config)
    ranked = score_files(files)[: config.max_files]
    print(f"Dry run: {len(files)} candidate files; top {len(ranked)} by heuristic:\n")
    for scored in ranked:
        tags = ", ".join(scored.categories) or "—"
        print(f"  [{scored.score:>3}] {scored.source.rel_path}  ({tags})")
    if config.enable_tools:
        tools = available_tools()
        names = ", ".join(t.name for t in tools) or "none on PATH"
        print(f"\nExternal SAST tools available: {names}")
    print(
        "\nNo validation/critic API calls were made. "
        "Run without --dry-run to scan."
    )
    return 0


async def _run_scan(config: ScanConfig) -> int:
    if "ANTHROPIC_API_KEY" not in os.environ and "ANTHROPIC_AUTH_TOKEN" not in os.environ:
        print(
            "error: ANTHROPIC_API_KEY (or ANTHROPIC_AUTH_TOKEN) is not set.",
            file=sys.stderr,
        )
        return 2

    llm = LLMClient(verbose=config.verbose)
    orchestrator = Orchestrator(config, llm)
    result = await orchestrator.run()

    report = render_markdown(result)
    config.output.write_text(report, encoding="utf-8")
    print(f"Wrote report to {config.output} "
          f"({len(result.accepted)} accepted, {len(result.appendix)} in appendix).")

    if config.json_output is not None:
        config.json_output.write_text(result.model_dump_json(indent=2), encoding="utf-8")
        print(f"Wrote machine-readable findings to {config.json_output}.")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )

    if not args.path.exists():
        print(f"error: path does not exist: {args.path}", file=sys.stderr)
        return 2

    config = _config_from_args(args)
    if config.dry_run:
        return _run_dry(config)
    return asyncio.run(_run_scan(config))


if __name__ == "__main__":
    raise SystemExit(main())
