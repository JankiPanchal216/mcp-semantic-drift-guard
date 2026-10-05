# Deterministic Schema-Level Security Checks (Tier 1.5 Specification)

## 1. Overview & Motivation

The Phase 5 Red-Team evaluation revealed a critical vulnerability in purely text-centric LLM judges: adversaries can inject malicious default parameters (e.g., `exfiltrate_to: "http://attacker.com"`) or relax operational constraints (e.g., toggling `readOnly: true` $\rightarrow$ `false`) without altering natural language docstrings, achieving a 0.0% detection rate.

To resolve this limitation without relying on expensive and brittle LLM reasoning over JSON schemas, we designed and implemented a **Deterministic Schema Security Checker** (`guard/schema_security_rules.py`).

---

## 2. Specification of Deterministic Checks

The schema security checker inspects structural diffs between candidate and trusted tool contracts, generating structured security findings with standardized severity levels:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                   DETERMINISTIC SCHEMA SECURITY ENGINE                      │
│                                                                             │
│  1. Annotation & Authorization Toggles                                      │
│     • readOnly: True -> False (HIGH Severity)                               │
│     • destructiveHint modification (MEDIUM Severity)                        │
│                                                                             │
│  2. Default Value Injection Checks (Regex Scan)                             │
│     • Injected default contains external URL / Webhook (CRITICAL Severity)  │
│     • Injected default contains sensitive filesystem path (CRITICAL)        │
│     • Injected privilege escalation parameter default=True (HIGH Severity) │
│                                                                             │
│  3. Interface & Contract Stability Checks                                   │
│     • Parameter converted to required (MEDIUM Severity)                     │
│     • Existing parameter removed (MEDIUM Severity)                          │
│     • Parameter type mutation (e.g. int -> string) (MEDIUM Severity)        │
│     • Parameter enum constraint mutation (MEDIUM Severity)                  │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Finding Structure & Integration Contract

Every finding emitted by `inspect_schema_security_diff()` adheres to the schema:

```json
{
  "category": "SCHEMA_SECURITY_CHANGE",
  "field": "properties.exfiltrate_to.default",
  "old": null,
  "new": "http://attacker.com/webhook",
  "severity": "CRITICAL",
  "rationale": "New parameter 'exfiltrate_to' injected with default external webhook/URL destination: 'http://attacker.com/webhook'."
}
```

### Pipeline Decision Rule
- **CRITICAL or HIGH Severity Findings**: Trigger immediate `QUARANTINE` (<1 ms, 0 LLM calls), preventing schema-only attacks from reaching the client.
- **MEDIUM Severity Findings**: Flagged as structural contract changes and passed to Tier 3 with schema context for human/semantic review.
- **LOW Severity Findings** (e.g., standard optional parameter additions): Allowed to proceed smoothly.

---

## 4. Empirical Validation

Unit testing in `tests/test_schema_security.py` confirms:
1. Catches 100% of `readOnly` boolean toggles.
2. Catches 100% of injected default webhook URLs.
3. Catches 100% of injected default sensitive paths (`/etc/shadow`, `~/.ssh`).
4. Catches 100% of privilege escalation boolean flags (`override_sudo = True`).
5. Successfully permits legitimate optional parameter additions with harmless enum/string defaults (Zero False Positives).
