"""Token-free heuristic risk scoring to prioritize files for analysis.

This is the cheap first pass: regex/keyword signals for the high-risk
categories named in the methodology. It ranks files so ``--max-files`` can cap
analysis at the most promising candidates before any tokens are spent.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .walker import SourceFile

# Category -> compiled signal patterns. Deliberately broad (recall-biased);
# the LLM stages filter false positives downstream.
RISK_CATEGORIES: dict[str, list[re.Pattern[str]]] = {
    "command_exec": [
        re.compile(r"\bos\.system\b"),
        re.compile(r"\bsubprocess\.(?:call|run|Popen|check_output)\b"),
        re.compile(r"\b(?:eval|exec)\s*\("),
        re.compile(r"shell\s*=\s*True"),
        re.compile(r"\bRuntime\.getRuntime\(\)\.exec\b"),
        re.compile(r"\bchild_process\b"),
    ],
    "sql_injection": [
        re.compile(r"(?:execute|executemany|query|raw)\s*\(.*[\"'].*%[s]?.*\+", re.S),
        re.compile(r"(?:SELECT|INSERT|UPDATE|DELETE)\b.*\+\s*\w", re.I),
        re.compile(r"f[\"'].*(?:SELECT|INSERT|UPDATE|DELETE)\b", re.I),
        re.compile(r"\.format\s*\(.*(?:SELECT|INSERT|UPDATE|DELETE)", re.I),
    ],
    "deserialization": [
        re.compile(r"\bpickle\.loads?\b"),
        re.compile(r"\byaml\.load\s*\((?!.*Loader)"),
        re.compile(r"\bmarshal\.loads?\b"),
        re.compile(r"\bObjectInputStream\b"),
        re.compile(r"\bunserialize\s*\("),
    ],
    "ssrf_network": [
        re.compile(r"\brequests\.(?:get|post|put|delete|head|request)\b"),
        re.compile(r"\burllib(?:2)?\.(?:urlopen|request)\b"),
        re.compile(r"\bhttpx\.(?:get|post|Client)\b"),
        re.compile(r"\bsocket\.(?:socket|connect)\b"),
        re.compile(r"\bfetch\s*\("),
    ],
    "path_traversal": [
        re.compile(r"open\s*\(.*(?:\+|%|format|join)\s*.*(?:request|param|input|arg)", re.I),
        re.compile(r"\b(?:send_file|sendfile|readFile|File)\s*\(.*(?:\+|join)"),
        re.compile(r"\.\./"),
        re.compile(r"os\.path\.join\(.*(?:request|param|input|user)", re.I),
    ],
    "secrets": [
        re.compile(r"(?i)(?:password|passwd|secret|api[_-]?key|token|access[_-]?key)\s*=\s*[\"'][^\"']{6,}"),
        re.compile(r"AKIA[0-9A-Z]{16}"),
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        re.compile(r"(?i)bearer\s+[a-z0-9._\-]{16,}"),
    ],
    "crypto": [
        re.compile(r"\b(?:md5|sha1)\b", re.I),
        re.compile(r"\bDES\b|\bECB\b"),
        re.compile(r"\brandom\.(?:random|randint|choice)\b"),
        re.compile(r"verify\s*=\s*False"),
        re.compile(r"\bssl\._create_unverified_context\b"),
    ],
    "auth": [
        re.compile(r"(?i)\b(?:login|authenticate|authorize|jwt|session)\b"),
        re.compile(r"(?i)verify.{0,12}(?:token|signature|password)"),
        re.compile(r"==\s*[\"'].*(?:password|secret|token)", re.I),
    ],
}

# Filenames that tend to concentrate risk get a bonus.
_HOT_FILENAME = re.compile(
    r"(?i)(auth|login|crypt|secret|password|admin|upload|exec|query|api|user)"
)


@dataclass
class ScoredFile:
    """A source file with its heuristic risk score and matched categories."""

    source: SourceFile
    score: int = 0
    categories: list[str] = field(default_factory=list)


def score_files(files: list[SourceFile]) -> list[ScoredFile]:
    """Score and rank ``files`` by heuristic likelihood of a real weakness."""
    scored: list[ScoredFile] = []
    for sf in files:
        score = 0
        categories: list[str] = []
        for category, patterns in RISK_CATEGORIES.items():
            hits = sum(1 for pat in patterns if pat.search(sf.text))
            if hits:
                # Diminishing returns per category; first hit weighted most.
                score += 3 + (hits - 1)
                categories.append(category)
        if _HOT_FILENAME.search(sf.rel_path):
            score += 2
        scored.append(ScoredFile(source=sf, score=score, categories=categories))

    scored.sort(key=lambda s: (-s.score, s.source.rel_path))
    return scored
