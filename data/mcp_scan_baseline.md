# mcp-scan Baseline

## Version
- **Tool / Package**: `snyk-agent-scan` (formerly `mcp-scan`, originally published by Invariant Labs, now maintained under Snyk Agent Scan)
- **Version**: `0.6.8` (verified via package metadata and CLI inspection)
- **Command Used**: `uvx --from snyk-agent-scan python -c "from agent_scan.run import run; run()"` (and `agent_scan.inspect`)

## Tool Pinning Mechanism
Tool pinning is an integrity verification and drift detection mechanism designed to mitigate "rug pull" and tool poisoning attacks in the Model Context Protocol ecosystem. 

When an MCP client or security scanner first discovers and approves an MCP server's tools, it computes a cryptographic hash (typically SHA-256) of each tool's definition to establish a trusted baseline. On subsequent scans, server initializations, or runtime tool invocations, the scanner or client recalculates the cryptographic hash of the currently advertised tool definition and compares it against the pinned baseline hash.

If the recomputed hash matches the baseline, the tool is verified as unchanged. If the recomputed hash differs from the baseline hash, the tool is flagged as having drifted or modified.

## Hashed Data
The tool definition fields hashed to generate a pin include:
- `name`: The identifier string of the tool (e.g., `"test_tool"`, `"read_file"`).
- `description`: The natural language docstring/description provided to the LLM directing tool usage.
- `inputSchema`: The JSON Schema specification of parameter names, types, descriptions, constraints, and required fields.
- Additional metadata/annotations where supported (such as `readOnlyHint`, `destructiveHint`, or output schemas).

A canonicalized JSON representation (e.g., keys sorted lexicographically, normalized whitespace, UTF-8 encoded) is digested using SHA-256 to ensure determinism across execution environments.

## Change Detection
Change detection operates via strict cryptographic equality:
```text
hash(current_tool_definition) == pinned_baseline_hash
```
1. **Initial Phase (Pinning / Baseline Establishment)**: The tool manifest is retrieved via standard MCP protocol handshake (`tools/list`). The canonical tool definition is hashed and recorded in a lockfile, configuration database, or scanner storage (`--storage-file` or `.mcp-pinned.json`).
2. **Evaluation Phase (Integrity Check)**: When the server is scanned or invoked again, the scanner issues a new `tools/list` call, recomputes the SHA-256 hash of the retrieved tool manifest, and checks it against the recorded baseline.
3. **Mismatch Signaling**: Any bit-level modification produces a completely different SHA-256 digest (avalanche effect). The scanner flags a hash mismatch error/warning (e.g., `"Tool definition changed"`, `"Hash mismatch"`, or `"Drift detected"`).

## Legitimate Updates
**mcp-scan / hash-based pinning CANNOT distinguish between benign tool updates and malicious tool poisoning.**

- **Benign updates**: Clarifying phrasing, fixing documentation typos, updating examples, or adding non-breaking descriptive guidance.
- **Malicious changes**: Injecting prompt override payloads (`<IMPORTANT>`), embedding unauthorized prerequisite steps (e.g., overwriting SSH keys), or manipulating tool arguments.

Because cryptographic hashing is completely blind to semantics, both benign clarifications and malicious attacks cause a hash divergence, producing an identical `MISMATCH / DRIFT DETECTED` outcome.

**This is the core research gap addressed by our MCP Semantic Drift Research**: Hash comparison alone is insufficient for practical maintenance of MCP servers because it produces frequent false positive alerts on legitimate software evolution.

## Research Relevance
Hash-based detection is the established security baseline in existing literature and tooling (e.g., `mcp-scan`, `mcp-audit`), not our contribution. While effective against silent tampering, its fundamental weakness is rigidity:

1. **High False Alarm Rate**: Every legitimate documentation update, parameter description refinement, or developer commit triggers a security alert, leading to alert fatigue or requiring manual re-approval friction.
2. **All-or-Nothing Model**: Cryptographic hashes are binary flags (0 or 1). They provide zero insight into *why* the tool changed or *what* the change implies for agent safety.
3. **Need for a Semantic Drift Judge**: Our future research contribution will build a semantic drift judge that evaluates the *intent and behavioral impact* of tool definition changes, reliably allowing legitimate updates while intercepting malicious deviations.
