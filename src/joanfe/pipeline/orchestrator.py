"""Drives stages a-f: triage -> discovery -> validation -> critic -> dedupe ->
synthesis, with bounded concurrency and the accept/appendix split."""

from __future__ import annotations

import asyncio
import logging

from ..config import ScanConfig
from ..ingest import walk_repo
from ..ingest.walker import SourceFile
from ..llm import LLMClient
from ..schema.finding import Candidate, CriticVerdict, Finding
from ..schema.report import ScanResult
from ..tools import available_tools
from . import critic, discovery, synthesize, triage, validation
from .dedupe import dedupe

logger = logging.getLogger("joanfe.pipeline")


class Orchestrator:
    """Runs the full scan pipeline for one :class:`ScanConfig`."""

    def __init__(self, config: ScanConfig, llm: LLMClient) -> None:
        self.config = config
        self.llm = llm
        self._sem = asyncio.Semaphore(config.concurrency)
        self.tools = available_tools() if config.enable_tools else []

    async def _bounded(self, coro):
        async with self._sem:
            return await coro

    async def run(self) -> ScanResult:
        config = self.config
        files = walk_repo(config)
        logger.info("walk found %d candidate source files", len(files))

        ranked = await triage.triage(files, config, self.llm)
        sources: dict[str, SourceFile] = {s.source.rel_path: s.source for s in ranked}

        # Stage (b): discovery, concurrent across files.
        discovery_tasks = [
            self._bounded(discovery.discover_in_file(scored, config, self.llm))
            for scored in ranked
        ]
        candidate_lists = await asyncio.gather(*discovery_tasks)
        candidates: list[Candidate] = [c for sub in candidate_lists for c in sub]
        logger.info("discovery produced %d candidates", len(candidates))

        # Stage (c): validation, concurrent across candidates.
        validate_tasks = [
            self._bounded(
                validation.validate_candidate(
                    cand,
                    sources,
                    config,
                    self.llm,
                    tools=self.tools,
                    repo_root=config.target if config.target.is_dir() else None,
                )
            )
            for cand in candidates
        ]
        validated = await asyncio.gather(*validate_tasks)

        accepted_findings: list[Finding] = []
        appendix: list[Finding] = []
        for finding, ok in validated:
            (accepted_findings if ok else appendix).append(finding)

        # Stage (d): adversarial critic, concurrent across accepted findings.
        critic_tasks = [
            self._bounded(critic.review_finding(f, config, self.llm))
            for f in accepted_findings
        ]
        reviewed = await asyncio.gather(*critic_tasks) if critic_tasks else []

        # Stage (e): dedupe survivors.
        survivors = [f for f in reviewed if f.critic_verdict != CriticVerdict.REJECTED]
        rejected = [f for f in reviewed if f.critic_verdict == CriticVerdict.REJECTED]
        survivors = dedupe(survivors)

        # Threshold split: below-threshold findings go to the appendix.
        accepted: list[Finding] = []
        for finding in survivors:
            if config.confidence_meets_threshold(finding.confidence):
                accepted.append(finding)
            else:
                finding.rejection_reason = (
                    finding.rejection_reason
                    or f"Confidence {finding.confidence.value} below threshold "
                    f"{config.min_confidence.value}."
                )
                appendix.append(finding)
        appendix.extend(rejected)

        self._assign_ids(accepted, appendix)

        # Stage (f): synthesis.
        return await synthesize.synthesize(
            accepted,
            appendix,
            config,
            self.llm,
            files_scanned=len(ranked),
            files_considered=len(files),
        )

    @staticmethod
    def _assign_ids(accepted: list[Finding], appendix: list[Finding]) -> None:
        for i, finding in enumerate(accepted, start=1):
            finding.finding_id = f"JF-{i:03d}"
        for j, finding in enumerate(appendix, start=1):
            finding.finding_id = f"JF-APX-{j:03d}"
