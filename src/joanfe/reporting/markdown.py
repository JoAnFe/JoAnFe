"""Render a :class:`ScanResult` to a Markdown report.

Pure function of the result — takes a ScanResult, returns a string. No API
calls, so it golden-tests trivially. The structure follows the README
methodology: per-finding sections render the full CWE -> ATT&CK chain.
"""

from __future__ import annotations

from ..schema.finding import Finding, Severity
from ..schema.report import ScanResult

_SEVERITY_LABEL = {
    Severity.CRITICAL: "Critical",
    Severity.HIGH: "High",
    Severity.MEDIUM: "Medium",
    Severity.LOW: "Low",
    Severity.INFO: "Info",
}


def render_markdown(result: ScanResult) -> str:
    parts: list[str] = []
    parts.append(f"# Security Scan Report\n\n**Target:** `{result.target}`\n")
    parts.append(
        f"**Files scanned:** {result.files_scanned} of "
        f"{result.files_considered} considered  \n"
        f"**Accepted findings:** {len(result.accepted)}  \n"
        f"**Appendix (rejected / low-confidence):** {len(result.appendix)}\n"
    )

    parts.append("## Executive Summary\n")
    parts.append((result.executive_summary or "_No summary available._") + "\n")

    parts.append(_severity_confidence_section(result))
    parts.append(_attack_coverage_section(result))

    parts.append("## Findings\n")
    if result.accepted:
        for finding in result.sorted_accepted():
            parts.append(_finding_section(finding))
    else:
        parts.append("_No findings met the confidence threshold._\n")

    parts.append(_appendix_section(result))
    parts.append(_footer(result))
    return "\n".join(parts)


def _severity_confidence_section(result: ScanResult) -> str:
    matrix = result.severity_confidence_matrix()
    if not matrix:
        return "## Severity x Confidence\n\n_No accepted findings._\n"
    lines = ["## Severity x Confidence\n", "| Severity | Confidence | Count |", "|---|---|---|"]
    for (sev, conf), count in sorted(matrix.items(), key=lambda kv: str(kv[0])):
        lines.append(f"| {_SEVERITY_LABEL[sev]} | {conf.value} | {count} |")
    return "\n".join(lines) + "\n"


def _attack_coverage_section(result: ScanResult) -> str:
    coverage = result.attack_coverage()
    if not coverage:
        return "## MITRE ATT&CK Coverage\n\n_No techniques mapped._\n"
    lines = ["## MITRE ATT&CK Coverage\n", "| Technique | Findings |", "|---|---|"]
    for technique, count in sorted(coverage.items(), key=lambda kv: -kv[1]):
        lines.append(f"| {technique} | {count} |")
    return "\n".join(lines) + "\n"


def _finding_section(f: Finding) -> str:
    lines = [
        f"### {f.finding_id}: {f.title}\n",
        f"- **CWE:** {f.cwe_id} {f.cwe_name}",
        f"- **Severity:** {_SEVERITY_LABEL[f.severity]}  |  "
        f"**Confidence:** {f.confidence.value}  |  "
        f"**Critic verdict:** {f.critic_verdict.value}",
        f"- **Exploit primitive:** {f.exploit_primitive}",
    ]
    if f.corroborating_tools:
        lines.append(f"- **Corroborated by:** {', '.join(f.corroborating_tools)}")
    lines.append("")

    lines.append("**Methodology chain**\n")
    lines.append(f"- _Weakness mechanism:_ {f.weakness_mechanism}")
    lines.append(_bullet_list("Exploit preconditions", f.exploit_preconditions))
    lines.append(f"- _Exploit primitive:_ {f.exploit_primitive}")
    lines.append(_bullet_list("Exploit outcomes", f.exploit_outcomes))
    lines.append(f"- _Adversary behaviour:_ {f.adversary_behaviour}")
    if f.reachability_rationale:
        lines.append(f"- _Reachability:_ {f.reachability_rationale}")
    lines.append("")

    if f.attack_mappings:
        lines.append("**MITRE ATT&CK**\n")
        for m in f.attack_mappings:
            lines.append(
                f"- **{m.technique_id} {m.technique_name}** "
                f"({m.tactic}) — {m.mapping_justification}"
            )
        lines.append("")

    if f.evidence:
        lines.append("**Evidence**\n")
        for cite in f.evidence:
            lines.append(f"`{cite.file_path}:{cite.start_line}-{cite.end_line}`")
            lines.append("```\n" + cite.snippet + "\n```")
            lines.append(f"_{cite.rationale}_\n")

    lines.append(_bullet_list("Assumptions", f.assumptions))
    lines.append(_bullet_list("Detection gaps", f.detection_gaps))
    if f.risk_narrative:
        lines.append(f"**Risk narrative:** {f.risk_narrative}\n")
    if f.recommendation:
        lines.append(f"**Recommendation:** {f.recommendation}\n")
    lines.append("---\n")
    return "\n".join(line for line in lines if line is not None)


def _appendix_section(result: ScanResult) -> str:
    if not result.appendix:
        return "## Appendix: Rejected / Low-Confidence Findings\n\n_None._\n"
    lines = [
        "## Appendix: Rejected / Low-Confidence Findings\n",
        "_Retained for transparency so suppression decisions are auditable._\n",
        "| ID | Title | CWE | Confidence | Verdict | Reason |",
        "|---|---|---|---|---|---|",
    ]
    for f in result.appendix:
        reason = (f.rejection_reason or "; ".join(f.critic_reasons) or "—").replace(
            "|", "\\|"
        )
        lines.append(
            f"| {f.finding_id} | {f.title} | {f.cwe_id} | {f.confidence.value} | "
            f"{f.critic_verdict.value} | {reason} |"
        )
    return "\n".join(lines) + "\n"


def _footer(result: ScanResult) -> str:
    models = ", ".join(f"{k}={v}" for k, v in result.model_summary.items())
    lines = ["## Scan Metadata\n", f"- **Models:** {models}"]
    if result.usage_summary:
        lines.append("- **Usage:**")
        lines.append("```\n" + result.usage_summary + "\n```")
    return "\n".join(lines) + "\n"


def _bullet_list(label: str, items: list[str]) -> str:
    if not items:
        return f"- _{label}:_ none recorded"
    inner = "\n".join(f"  - {item}" for item in items)
    return f"- _{label}:_\n{inner}"
