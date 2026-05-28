"""Shared test fixtures: a no-token FakeAnthropic seam and a scripted responder.

The pipeline depends only on ``LLMClient``'s wrapped client exposing
``messages.parse``, so injecting a fake exercises orchestration, the critic
loop, dedupe, thresholding, and report assembly without any API calls.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import pytest

from joanfe.pipeline.synthesize import _ExecutiveSummary
from joanfe.pipeline.triage import FileTriage, TriageBatch
from joanfe.schema.finding import (
    AttackMapping,
    Candidate,
    CandidateBatch,
    Confidence,
    CriticVerdict,
    EvidenceCitation,
    Finding,
    Severity,
)

FIXTURE_REPO = Path(__file__).parent / "fixtures" / "vuln_repo"


def pytest_addoption(parser):
    parser.addoption(
        "--run-live",
        action="store_true",
        default=False,
        help="Run tests marked @pytest.mark.live against the real Anthropic API.",
    )


def pytest_collection_modifyitems(config, items):
    if config.getoption("--run-live"):
        return
    skip = pytest.mark.skip(reason="needs --run-live and ANTHROPIC_API_KEY")
    for item in items:
        if "live" in item.keywords:
            item.add_marker(skip)


# rel_path -> seeded vulnerability template.
@dataclass
class VulnSpec:
    cwe_id: str
    cwe_name: str
    primitive: str
    technique_id: str
    technique_name: str
    tactic: str
    marker: str  # substring identifying the vulnerable line


VULN_REGISTRY: dict[str, VulnSpec] = {
    "cmd_exec.py": VulnSpec(
        "CWE-78", "OS Command Injection", "command execution",
        "T1059", "Command and Scripting Interpreter", "Execution", "os.system",
    ),
    "sqli.py": VulnSpec(
        "CWE-89", "SQL Injection", "query manipulation",
        "T1213", "Data from Information Repositories", "Collection", "cursor.execute",
    ),
    "deser.py": VulnSpec(
        "CWE-502", "Deserialization of Untrusted Data", "remote code execution",
        "T1203", "Exploitation for Client Execution", "Execution", "pickle.loads",
    ),
    "secret.py": VulnSpec(
        "CWE-798", "Use of Hard-coded Credentials", "credential exposure",
        "T1078", "Valid Accounts", "Initial Access", "API_KEY =",
    ),
    "ssrf.py": VulnSpec(
        "CWE-918", "Server-Side Request Forgery", "server-side request manipulation",
        "T1090", "Proxy", "Command and Control", "requests.get",
    ),
    "traversal.py": VulnSpec(
        "CWE-22", "Path Traversal", "arbitrary file read",
        "T1005", "Data from Local System", "Collection", "os.path.join",
    ),
}


class _Usage:
    input_tokens = 100
    output_tokens = 50
    cache_read_input_tokens = 80
    cache_creation_input_tokens = 0


class _Response:
    def __init__(self, parsed) -> None:
        self.parsed_output = parsed
        self.usage = _Usage()


class _Messages:
    def __init__(self, responder) -> None:
        self._responder = responder

    async def parse(self, **kwargs):
        system = kwargs["system"][0]["text"]
        user = kwargs["messages"][0]["content"]
        output_format = kwargs["output_format"]
        return _Response(self._responder(system, user, output_format))


class FakeAnthropic:
    """Drop-in stand-in for ``AsyncAnthropic`` driven by a responder callable."""

    def __init__(self, responder) -> None:
        self.messages = _Messages(responder)


def _line_for(rel_path: str, marker: str) -> tuple[int, str]:
    text = (FIXTURE_REPO / rel_path).read_text()
    for i, line in enumerate(text.splitlines(), start=1):
        if marker in line:
            return i, line
    return 1, text.splitlines()[0]


def scripted_responder(system: str, user: str, output_format):
    """Deterministic responses for the fixture repo — no network."""
    if output_format is TriageBatch:
        paths = re.findall(r"path:\s*(\S+)", user)
        return TriageBatch(
            files=[
                FileTriage(
                    file_path=p,
                    likelihood=90 if Path(p).name in VULN_REGISTRY else 30,
                    category="security",
                )
                for p in paths
            ]
        )

    if output_format is CandidateBatch:
        rel = re.search(r"File:\s*(\S+)", user)
        rel_path = rel.group(1) if rel else ""
        name = Path(rel_path).name
        if name in VULN_REGISTRY:
            spec = VULN_REGISTRY[name]
            line, _ = _line_for(rel_path, spec.marker)
            return CandidateBatch(
                candidates=[
                    Candidate(
                        title=f"{spec.cwe_name} in {name}",
                        cwe_id=spec.cwe_id,
                        file_path=rel_path,
                        start_line=line,
                        end_line=line,
                        reason="user input reaches a dangerous sink",
                        provisional_confidence=Confidence.MEDIUM,
                    )
                ]
            )
        if name == "notes.py":
            # A weak candidate that must fail the evidence gate downstream.
            return CandidateBatch(
                candidates=[
                    Candidate(
                        title="Possible issue in notes.py",
                        cwe_id="CWE-000",
                        file_path=rel_path,
                        start_line=1,
                        end_line=1,
                        reason="speculative",
                    )
                ]
            )
        return CandidateBatch(candidates=[])

    if output_format is Finding:
        if "TASK: Adversarial review" in system:
            return _critic_response(user)
        return _validation_response(user)

    if output_format is _ExecutiveSummary:
        return _ExecutiveSummary(summary="Scripted summary of validated findings.")

    raise AssertionError(f"unexpected output_format {output_format!r}")


def _validation_response(user: str) -> Finding:
    cand = re.search(r'"file_path":\s*"([^"]+)"', user)
    rel_path = cand.group(1) if cand else ""
    name = Path(rel_path).name

    if name not in VULN_REGISTRY:
        # Evidence-less finding: fails the hard gate, lands in the appendix.
        return Finding(
            title="Unsubstantiated finding",
            cwe_id="CWE-000",
            cwe_name="Unknown",
            weakness_mechanism="No real weakness identified.",
            exploit_primitive="none",
            adversary_behaviour="none",
            confidence=Confidence.LOW,
            severity=Severity.INFO,
            rejection_reason="No exploitable behaviour found.",
        )

    spec = VULN_REGISTRY[name]
    line, code = _line_for(rel_path, spec.marker)
    return Finding(
        title=f"{spec.cwe_name} in {name}",
        cwe_id=spec.cwe_id,
        cwe_name=spec.cwe_name,
        weakness_mechanism=f"Untrusted input reaches a {spec.primitive} sink.",
        exploit_preconditions=["network-reachable endpoint", "attacker-controlled input"],
        exploit_primitive=spec.primitive,
        exploit_outcomes=["compromise of confidentiality or integrity"],
        adversary_behaviour="Attacker drives the input to gain the primitive.",
        attack_mappings=[
            AttackMapping(
                tactic=spec.tactic,
                technique_id=spec.technique_id,
                technique_name=spec.technique_name,
                mapping_justification=(
                    f"The {spec.primitive} primitive enables behaviour mapped to "
                    f"{spec.technique_id}."
                ),
            )
        ],
        reachability_rationale="Source parameter flows unsanitized to the sink.",
        confidence=Confidence.HIGH,
        severity=Severity.HIGH,
        evidence=[
            EvidenceCitation(
                file_path=rel_path,
                start_line=line,
                end_line=line,
                snippet=code,
                rationale="The vulnerable sink.",
            )
        ],
        assumptions=["input is attacker-controlled"],
        detection_gaps=["no input-validation logging"],
        risk_narrative="Exploitation could lead to system compromise.",
        recommendation="Validate and parameterize untrusted input.",
    )


def _critic_response(user: str) -> Finding:
    finding = Finding.model_validate_json(_extract_json(user))
    finding.critic_verdict = CriticVerdict.CONFIRMED
    return finding


def _extract_json(user: str) -> str:
    start = user.index("{")
    # Find the matching closing brace for the first JSON object.
    depth = 0
    for i in range(start, len(user)):
        if user[i] == "{":
            depth += 1
        elif user[i] == "}":
            depth -= 1
            if depth == 0:
                return user[start : i + 1]
    return user[start:]


@pytest.fixture
def fake_llm():
    """An ``LLMClient`` wired to the scripted fake — no network, no API key."""
    from joanfe.llm import LLMClient

    return LLMClient(client=FakeAnthropic(scripted_responder), verbose=False)
