"""Stage (f): synthesis into a ScanResult, including the executive summary."""

from __future__ import annotations

import json

from ..config import ScanConfig
from ..llm import LLMClient, prompts
from ..schema.finding import Finding
from ..schema.report import ScanResult


def _summary_payload(findings: list[Finding]) -> str:
    rows = [
        {
            "title": f.title,
            "cwe": f.cwe_id,
            "severity": f.severity.value,
            "confidence": f.confidence.value,
            "primitive": f.exploit_primitive,
            "attack": [m.technique_id for m in f.attack_mappings],
        }
        for f in findings
    ]
    return json.dumps(rows, indent=2)


async def synthesize(
    accepted: list[Finding],
    appendix: list[Finding],
    config: ScanConfig,
    llm: LLMClient | None,
    files_scanned: int,
    files_considered: int,
) -> ScanResult:
    """Assemble the final ScanResult and author the executive summary."""
    result = ScanResult(
        target=str(config.target),
        files_scanned=files_scanned,
        files_considered=files_considered,
        accepted=accepted,
        appendix=appendix,
        model_summary={
            "triage": config.models.triage,
            "discovery": config.models.discovery,
            "validation": config.models.validation,
            "critic": config.models.critic,
            "synthesis": config.models.synthesis,
        },
    )

    if accepted and llm is not None:
        try:
            summary_obj = await llm.parse(
                stage="synthesis",
                model=config.models.synthesis,
                system=prompts.SYNTHESIS_SYSTEM,
                user_content=prompts.synthesis_user(
                    _summary_payload(accepted), str(config.target)
                ),
                output_format=_ExecutiveSummary,
                max_tokens=2000,
            )
            result.executive_summary = summary_obj.summary
        except Exception:  # noqa: BLE001 - summary is non-critical
            result.executive_summary = _fallback_summary(accepted)
    else:
        result.executive_summary = _fallback_summary(accepted)

    if llm is not None:
        result.usage_summary = llm.usage.summary()
    return result


def _fallback_summary(accepted: list[Finding]) -> str:
    if not accepted:
        return "No weaknesses met the confidence threshold for this scan."
    by_cwe = sorted({f.cwe_id for f in accepted})
    return (
        f"{len(accepted)} weakness(es) were validated across this codebase, "
        f"spanning {len(by_cwe)} CWE classes ({', '.join(by_cwe[:6])}). "
        "See per-finding sections for the full CWE -> ATT&CK chain and remediation."
    )


from pydantic import BaseModel  # noqa: E402 - kept local to the synthesis stage


class _ExecutiveSummary(BaseModel):
    summary: str
