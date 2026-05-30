## Vulnerability → Attack Path Workflow

A structured, evidence-led process for translating software weaknesses into attacker behaviour. Rather than mapping CWEs directly to MITRE ATT&CK tactics, this workflow evaluates vulnerability context, the exploit capability it creates, and the likely adversary actions that follow — creating a more defensible link between vulnerability management, threat modelling, exposure management, and operational detection.

```mermaid
flowchart TD
    A[Vulnerability / Finding Identified] --> B[Identify CWE]
    B --> C[Flag Weakness Mechanism - CWE]
    C --> D[Exploit Preconditions]
    D --> E[Exploit Primitive]
    E --> F[Likely Exploit Outcomes]
    F --> G[Adversary Behaviour]
    G --> H[MITRE ATT&CK Tactic / Technique]
    H --> I[Confidence Level]
    I --> J[Record Evidence, Assumptions and Detection Gaps]
    J --> K[Risk Narrative and Recommendation]
```

### Process Summary

| Step | Activity | Output |
|---:|---|---|
| 1 | Identify the vulnerability | CVE, internal finding ID, affected asset |
| 2 | Classify the weakness | CWE |
| 3 | Understand the weakness mechanism | Plain-language description of what is broken |
| 4 | Define exploit preconditions | Exposure, authentication, privilege, user interaction |
| 5 | Identify the exploit primitive | RCE, auth bypass, file read, credential exposure, SSRF |
| 6 | Assess exploit outcomes | What an attacker could realistically achieve |
| 7 | Translate to adversary behaviour | What an attacker would do during an intrusion |
| 8 | Map to MITRE ATT&CK | Relevant tactic and technique |
| 9 | Score confidence | High, medium, or low — based on evidence |
| 10 | Record evidence and assumptions | Audit trail for the mapping |
| 11 | Identify detection gaps | Logs, telemetry, alerts, visibility |
| 12 | Produce a recommendation | Remediation, compensating controls, ownership |

### Core Model

```
CWE              = weakness definition
Exploit primitive = the capability the attacker gains
Exploit outcome   = the risk — what the attacker can achieve
MITRE ATT&CK      = how that behaviour appears in an intrusion
```

### Example Mappings

| CWE | Exploit Primitive | Exploit Outcome | ATT&CK Interpretation |
|---|---|---|---|
| CWE-89 SQL Injection | Query manipulation | Credential extraction or database dumping | Credential Access / Collection / Exfiltration |
| CWE-918 SSRF | Server-side request manipulation | Cloud metadata access or internal service probing | Discovery / Credential Access |
| CWE-22 Path Traversal | Arbitrary file read | Secret, config, or key exposure | Credential Access / Collection |
| CWE-78 Command Injection | Command execution | Remote shell or system compromise | Execution / Persistence / Initial Access |
| CWE-798 Hardcoded Credentials | Credential exposure | Use of valid accounts | Credential Access / Initial Access / Lateral Movement |

### Analyst Rule

> Never map CWE directly to ATT&CK without context.

```
CWE → Exploit Primitive → Exploit Outcome → Adversary Behaviour → ATT&CK Technique
```

---

### How It Works

A **tool for defensive scanning** — a deterministic, code-orchestrated pipeline backed by an LLM of your choice:

1. **Triage** — risk scoring, refined by a lightweight model.
2. **Discovery** — recall-biased finding per file in the codebase.
3. **Validation** — re-examines each candidate in context, builds the full `CWE → primitive → outcome → adversary → ATT&CK` chain, and enforces a hard evidence gate (precondition + reachability + ≥1 verbatim citation).
4. **Critic** — a bounded adversarial loop that confirms, downgrades, or rejects each finding.
5. **Dedupe** — clusters overlapping findings.
6. **Synthesis** — assembles the final report; sub-threshold and rejected findings are retained in a transparency appendix.
