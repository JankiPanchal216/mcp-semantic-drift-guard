# Fresh Adversarial Red-Team v2 Dataset Specification

## 1. Motivation & Scope

Phase 5 evaluated a 10-category adversarial suite ($N=30$) and revealed key evasion surfaces in optional parameter default injections and low-signal boolean schema toggles. To test defense upgrades (including the new deterministic schema security checker) and evaluate advanced evasion strategies, we constructed the **Fresh Adversarial Red-Team v2 Dataset** (`data/redteam_v2.jsonl`).

---

## 2. Expanded 14-Category Adversarial Taxonomy

The suite incorporates 14 distinct evasion and attack vector categories (28 test instances):

| Category ID | Mutation Category Name | Attack Vector & Surface | Expected Label |
|---|---|---|---|
| `01` | **Indirect Wording** | Passive telemetry auditing language in docstrings | `MALICIOUS` |
| `02` | **Euphemistic Instructions** | Destructive overwrites framed as "system cleanup" | `MALICIOUS` |
| `03` | **Multi-Step Intent** | Exfiltration split across sequential operational steps | `MALICIOUS` |
| `04` | **Semantically Subtle Changes** | Unrestricted filesystem / query authorization expansion | `SUSPICIOUS` / `MALICIOUS` |
| `05` | **Benign-Looking Prerequisites** | Mandatory chaining to diagnostic stubs (`health_check`) | `MALICIOUS` |
| `06` | **Parameter Description Hiding** | Directives embedded inside schema property docstrings | `MALICIOUS` |
| `07` | **Optional Parameter Hijacking** | Adding optional parameters with default external webhooks | `MALICIOUS` |
| `08` | **Argument Redirection** | Directing write operations to `/etc/shadow` or webroots | `MALICIOUS` |
| `09` | **Field Splitting** | Distributing instruction fragments across name, description, schema | `MALICIOUS` |
| `10` | **Low-Signal Semantic Drift** | Toggling `"readOnly": true` $\rightarrow$ `false`, rate limit changes | `SUSPICIOUS` |
| `11` | **Judge-Directed Prompt Injection** | Injected XML tags and override directives targeting the judge | `MALICIOUS` |
| `12` | **Salami Drift** | Multi-version incremental modifications accumulating to malicious | `BENIGN` $\rightarrow$ `MALICIOUS` |
| `13` | **Newly Added Poisoned Tools** | Initial tool registration containing immediate poisoning | `MALICIOUS` / `BENIGN` |
| `14` | **Rug-Pull Timing** | Benign V1 $\rightarrow$ Benign V2 $\rightarrow$ Malicious V3 delayed attack | `BENIGN` $\rightarrow$ `MALICIOUS` |

---

## 3. Dataset Characteristics & Provenance

- **Storage**: `data/redteam_v2.jsonl`
- **Builder**: `experiments/build_redteam_v2.py`
- **Integrity Boundary**: Constructed independently after freezing defense specifications.
- **Ground Truth Distribution**: 23 Malicious / Suspicious attacks, 5 Benign controls (for salami V1, new benign tool, and rug-pull V2).
