"""JoAnFe — an agentic static code scanner.

Finds security weaknesses LLM-first, validates them through an adversarial
multi-pass pipeline, and emits a Markdown report implementing the evidence-led
methodology: CWE -> Exploit Preconditions -> Exploit Primitive -> Exploit
Outcomes -> Adversary Behaviour -> MITRE ATT&CK -> Confidence ->
Evidence/Assumptions/Detection Gaps -> Risk Narrative + Recommendation.
"""

__version__ = "0.1.0"
