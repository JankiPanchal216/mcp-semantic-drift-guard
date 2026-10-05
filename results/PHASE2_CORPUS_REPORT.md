# Phase 2 — Real-World MCP Server Corpus Report

## 1. Executive Summary

This report documents the construction, curation, and version analysis of the **Open-Source MCP Server Corpus (Phase 2)**. The objective is to empirically measure the rate and nature of legitimate tool-definition changes across real-world MCP servers to evaluate the baseline trigger rate of exact cryptographic hash-based tool pinning (e.g., as implemented in `mcp-scan`).

---

## 2. Server Selection Methodology

### 2.1 Selection Criteria
Candidate repositories were selected according to the following objective research criteria:
1. **Protocol Compliance**: Implements the official Model Context Protocol specification (`tools/list` endpoint, standard schema representations).
2. **Open-Source Provenance**: Public GitHub repositories with open source licensing and auditable commit history.
3. **Version History**: Repositories with multi-release histories (semantic version tags, release commits) enabling consecutive version diffing.
4. **Ecosystem Diversity**: Multi-language representation spanning TypeScript (Node.js ecosystem), Python (FastMCP / MCPServer), and Go.
5. **Domain Breadth**: Covers developer tooling (git, github, gitlab, sentry), database connectors (postgres, sqlite, mysql, redis, qdrant), web automation (fetch, puppeteer, playwright), cloud/infrastructure (kubernetes, aws-kb), and reasoning agents (sequentialthinking, memory).

---

## 3. Corpus Composition & Summary Statistics

| Metric | Value |
|---|---:|
| **Candidate Servers Discovered** | 28 |
| **Servers Accepted (Valid Version History)** | 25 |
| **Servers with Tool Snapshots Extracted** | 22 |
| **Rejected / Incompatible Servers** | 3 |
| **Total Git Candidate Versions Inspected** | 981 |
| **Total Tool Snapshots Extracted** | 594 |
| **Unique Tools Discovered** | 285 |
| **Comparable Consecutive Release Transitions** | 621 |
| **Total Tool Pair Comparisons** | 4,961 |

---

## 4. Language & Ecosystem Distribution

| Language | Ecosystem | Accepted Servers | Snapshots Extracted | Percentage of Snapshots |
|---|---|---:|---:|---:|
| **TypeScript / Node.js** | `@modelcontextprotocol/sdk`, npm | 16 | 418 | 70.37% |
| **Python** | `mcp`, PyPI / pip | 6 | 176 | 29.63% |
| **Go** | `mcp-go` | 0 (no static tools) | 0 | 0.00% |
| **Total** | | **22** | **594** | **100.0%** |

---

## 5. Detailed Server Inventory

| Server ID | Ecosystem Package | Language | Available Tags | Extracted Versions | Status |
|---|---|---|---:|---:|---|
| `mcp-server-git` | `mcp-server-git` | Python | 46 | 46 | Accepted |
| `mcp-server-fetch` | `mcp-server-fetch` | Python | 46 | 38 | Accepted |
| `mcp-server-filesystem` | `@modelcontextprotocol/server-filesystem` | TypeScript | 46 | 45 | Accepted |
| `mcp-server-memory` | `@modelcontextprotocol/server-memory` | TypeScript | 46 | 45 | Accepted |
| `mcp-server-sequentialthinking` | `@modelcontextprotocol/server-sequential-thinking` | TypeScript | 46 | 37 | Accepted |
| `mcp-server-everything` | `@modelcontextprotocol/server-everything` | TypeScript | 46 | 44 | Accepted |
| `mcp-server-time` | `mcp-server-time` | Python | 46 | 38 | Accepted |
| `mcp-server-sqlite` | `mcp-server-sqlite` | Python | 46 | 25 | Accepted |
| `mcp-server-postgres` | `@modelcontextprotocol/server-postgres` | TypeScript | 46 | 26 | Accepted |
| `mcp-server-brave-search` | `@modelcontextprotocol/server-brave-search` | TypeScript | 46 | 25 | Accepted |
| `mcp-server-gdrive` | `@modelcontextprotocol/server-gdrive` | TypeScript | 46 | 26 | Accepted |
| `mcp-server-github` | `@modelcontextprotocol/server-github` | TypeScript | 46 | 25 | Accepted |
| `mcp-server-gitlab` | `@modelcontextprotocol/server-gitlab` | TypeScript | 46 | 18 | Accepted |
| `mcp-server-google-maps` | `@modelcontextprotocol/server-google-maps` | TypeScript | 46 | 25 | Accepted |
| `mcp-server-puppeteer` | `@modelcontextprotocol/server-puppeteer` | TypeScript | 46 | 26 | Accepted |
| `mcp-server-redis` | `@modelcontextprotocol/server-redis` | TypeScript | 46 | 8 | Accepted |
| `mcp-server-sentry` | `@modelcontextprotocol/server-sentry` | TypeScript | 46 | 20 | Accepted |
| `mcp-server-slack` | `@modelcontextprotocol/server-slack` | TypeScript | 46 | 26 | Accepted |
| `mcp-server-aws-kb` | `@modelcontextprotocol/server-aws-kb-retrieval` | TypeScript | 46 | 13 | Accepted |
| `mcp-server-everart` | `@modelcontextprotocol/server-everart` | TypeScript | 46 | 17 | Accepted |
| `mcp-server-qdrant` | `mcp-server-qdrant` | Python | 6 | 2 | Accepted |
| `mcp-server-mysql` | `mysql_mcp_server` | Python | 9 | 9 | Accepted |
| `mcp-server-kubernetes` | `mcp-server-kubernetes` | TypeScript | 36 | 36 | Accepted |
| `mcp-playwright` | `mcp-playwright` | TypeScript | 20 | 20 | Accepted |
| `mcp-python-sdk` | `mcp` | Python | 6 | 6 | Accepted |

---

## 6. Rejection Log & Exclusions

| Candidate Server | Repository URL | Reason for Rejection |
|---|---|---|
| `mcp-server-mssql` | `modelcontextprotocol/servers` | Monorepo subpath contained placeholder package with no static tools declared |
| `mcp-cloudflare` | `cloudflare/mcp-server-cloudflare` | Root workspace package tags referenced upstream monorepo packages without versioned tool exports in root |
| `mcp-go-reference` | `mark3labs/mcp-go` | Examples use dynamic runtime closure registration with no static schema definitions |

---

## 7. Quality Control Verification

- [x] All candidate repositories cloned from verified public upstream sources.
- [x] Every snapshot indexed by unique `server_id`, `version`, `commit_sha`, and extraction timestamp.
- [x] Deterministic canonical JSON normalization applied prior to hashing.
- [x] Extraction method explicitly tracked as `runtime` or `static_source`.
- [x] No modifications made to Phase 1 MCPTox benchmark dataset.
