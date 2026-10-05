# MCP Semantic Drift Research

## Environment

### Operating System
Windows

### Python
3.11.9

### Package Manager
uv 0.12.23

### Version Control
Git 2.54.0.windows.1

### MCP
MCP Python SDK 2.3.0

### Local Model
Qwen3-8B

### Local Model Runtime
Ollama 0.35.1

### API Model
To be selected

### Generation Setting
Temperature: 0

## Project Structure

- data/ — MCP server data, tool definitions and labelled changes
- guard/ — semantic drift guard implementation
- experiments/ — experiment scripts
- results/ — experiment results, tables and analysis

## Research Goal

Study whether semantic analysis can distinguish benign MCP tool-definition
updates from malicious changes that would otherwise trigger hash-based
tool-pinning alerts.

## Reproducibility

Versions should be recorded before experiments are conducted.
Experimental settings should remain fixed unless a change is explicitly
documented.
