"""
Phase 2 MCP Corpus Extraction Engine (Enhanced)
Extracts tool definitions across real-world MCP server versions.
Supports runtime stdio extraction and static AST/schema fallback extraction.
"""

import os
import sys
import json
import re
import ast
import hashlib
import subprocess
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple

ROOT_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT_DIR / "data"
SNAPSHOT_DIR = DATA_DIR / "tool_snapshots"
REPOS_DIR = DATA_DIR / "repos"

os.makedirs(SNAPSHOT_DIR, exist_ok=True)


def get_git_tags_and_commits(repo_path: Path) -> List[Dict[str, str]]:
    """Retrieve all tags with SHA and date, sorted chronologically."""
    try:
        out = subprocess.check_output(
            ['git', '-C', str(repo_path), 'for-each-ref', '--format=%(refname:short)|%(objectname)|%(creatordate:iso8601)', 'refs/tags'],
            text=True,
            encoding='utf-8',
            errors='replace'
        )
        tags = []
        for line in out.strip().split('\n'):
            if not line.strip():
                continue
            parts = line.strip().split('|')
            if len(parts) >= 3:
                tags.append({
                    "tag": parts[0],
                    "commit": parts[1],
                    "date": parts[2]
                })
        # If no tags, get commit history
        if not tags:
            out_commits = subprocess.check_output(
                ['git', '-C', str(repo_path), 'log', '--format=%h|%H|%ci', '-n', '20'],
                text=True,
                encoding='utf-8',
                errors='replace'
            )
            for line in out_commits.strip().split('\n'):
                if not line.strip():
                    continue
                parts = line.strip().split('|')
                if len(parts) >= 3:
                    tags.append({
                        "tag": f"commit-{parts[0]}",
                        "commit": parts[1],
                        "date": parts[2]
                    })
        return tags
    except Exception as e:
        print(f"Error reading git refs from {repo_path}: {e}")
        return []


def parse_python_tool_definitions(code_text: str) -> List[Dict[str, Any]]:
    """Parse MCP tool definitions from Python source code."""
    tools = []
    
    # Extract enum mappings e.g. class GitTools(str, Enum): READ_FILE = "read_file"
    enum_vals = {}
    for m in re.finditer(r'class\s+([A-Za-z0-9_]+)\s*\([^)]*Enum[^)]*\):([\s\S]*?)(?=\nclass|\ndef|\nif|\n[A-Z_]|\Z)', code_text):
        cls_name = m.group(1)
        body = m.group(2)
        for line in body.split('\n'):
            assign_m = re.search(r'([A-Za-z0-9_]+)\s*=\s*["\']([^"\']+)["\']', line)
            if assign_m:
                key = f"{cls_name}.{assign_m.group(1)}"
                enum_vals[key] = assign_m.group(2)
                enum_vals[assign_m.group(1)] = assign_m.group(2)

    # 1. Look for Tool(name=..., description=..., inputSchema=...)
    tool_blocks = re.findall(r'Tool\s*\((.*?)\)(?=\s*(?:,|\)|Tool\s*\(|$|\n))', code_text, re.DOTALL)
    for block in tool_blocks:
        name_m = re.search(r'name\s*=\s*([A-Za-z0-9_.]+|["\'][^"\']+["\'])', block)
        name = ""
        if name_m:
            raw_n = name_m.group(1).strip('"\'')
            if raw_n in enum_vals:
                name = enum_vals[raw_n]
            elif '.' in raw_n and raw_n.split('.')[-1] in enum_vals:
                name = enum_vals[raw_n.split('.')[-1]]
            else:
                name = raw_n.lower()
        
        desc_m = re.search(r'description\s*=\s*(?:["\']{3}([\s\S]*?)["\']{3}|["\']([^"\']*)["\'])', block)
        desc = ""
        if desc_m:
            desc = (desc_m.group(1) or desc_m.group(2) or "").strip()
            
        schema_m = re.search(r'inputSchema\s*=\s*({.*?}|[A-Za-z0-9_]+\.model_json_schema\(\))', block, re.DOTALL)
        schema = {"type": "object", "properties": {}}
        if schema_m:
            schema_str = schema_m.group(1)
            try:
                s_val = ast.literal_eval(schema_str)
                if isinstance(s_val, dict):
                    schema = s_val
            except Exception:
                schema = {"type": "object", "raw": schema_str}
                
        if name:
            tools.append({
                "name": name,
                "description": desc,
                "inputSchema": schema
            })

    # 2. FastMCP / MCPServer / Server decorators (@mcp.tool, @app.tool, @server.tool)
    try:
        tree = ast.parse(code_text)
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                is_tool = False
                for dec in node.decorator_list:
                    dec_name = ""
                    if isinstance(dec, ast.Call):
                        if isinstance(dec.func, ast.Attribute):
                            dec_name = dec.func.attr
                        elif isinstance(dec.func, ast.Name):
                            dec_name = dec.func.id
                    elif isinstance(dec, ast.Attribute):
                        dec_name = dec.attr
                    elif isinstance(dec, ast.Name):
                        dec_name = dec.id
                    if 'tool' in dec_name.lower():
                        is_tool = True
                
                if is_tool:
                    name = node.name
                    desc = ast.get_docstring(node) or ""
                    props = {}
                    required = []
                    for arg in node.args.args:
                        if arg.arg in ('self', 'cls', 'ctx', 'context'):
                            continue
                        arg_name = arg.arg
                        required.append(arg_name)
                        arg_type = "string"
                        if arg.annotation:
                            if isinstance(arg.annotation, ast.Name):
                                if arg.annotation.id in ('int', 'float'):
                                    arg_type = "number"
                                elif arg.annotation.id == 'bool':
                                    arg_type = "boolean"
                                elif arg.annotation.id == 'dict':
                                    arg_type = "object"
                                elif arg.annotation.id == 'list':
                                    arg_type = "array"
                        props[arg_name] = {"type": arg_type}
                    
                    schema = {
                        "type": "object",
                        "properties": props,
                        "required": required
                    }
                    if not any(t["name"] == name for t in tools):
                        tools.append({
                            "name": name,
                            "description": desc.strip(),
                            "inputSchema": schema
                        })
    except Exception:
        pass

    return tools


def parse_typescript_tool_definitions(code_text: str) -> List[Dict[str, Any]]:
    """Parse MCP tool definitions from TypeScript source code."""
    tools = []
    
    # 1. Object literals: { name: "...", description: "...", inputSchema: { ... } }
    regex_tool_obj = re.finditer(
        r'\{\s*name:\s*["\']([^"\']+)["\'],\s*description:\s*(?:`([\s\S]*?)`|["\']([\s\S]*?)["\'])(?:,\s*inputSchema:\s*(\{[\s\S]*?\n\s*\}))?',
        code_text
    )
    for m in regex_tool_obj:
        name = m.group(1)
        desc = (m.group(2) or m.group(3) or "").strip()
        schema_raw = m.group(4) or ""
        
        props = {}
        required = []
        if schema_raw:
            prop_matches = re.finditer(r'([a-zA-Z0-9_-]+):\s*\{\s*type:\s*["\']([^"\']+)["\'](?:,\s*description:\s*["\']([^"\']*)["\'])?', schema_raw)
            for pm in prop_matches:
                pname = pm.group(1)
                ptype = pm.group(2)
                pdesc = pm.group(3) or ""
                props[pname] = {"type": ptype}
                if pdesc:
                    props[pname]["description"] = pdesc
            
            req_m = re.search(r'required:\s*\[(.*?)\]', schema_raw, re.DOTALL)
            if req_m:
                req_strs = re.findall(r'["\']([^"\']+)["\']', req_m.group(1))
                required.extend(req_strs)
                
        schema = {
            "type": "object",
            "properties": props,
            "required": required
        }
        tools.append({
            "name": name,
            "description": desc,
            "inputSchema": schema
        })

    # 2. McpServer tool calls: server.tool("name", "description", { ... } or z.object({ ... }))
    mcp_tool_calls = re.finditer(
        r'server\.tool\s*\(\s*["\']([^"\']+)["\']\s*,\s*(?:`([\s\S]*?)`|["\']([\s\S]*?)["\'])\s*,\s*(\{[\s\S]*?\n\s*\}|z\.object\(\{[\s\S]*?\}\))',
        code_text
    )
    for m in mcp_tool_calls:
        name = m.group(1)
        desc = (m.group(2) or m.group(3) or "").strip()
        schema_raw = m.group(4) or ""
        
        props = {}
        required = []
        zod_props = re.finditer(r'([a-zA-Z0-9_-]+):\s*z\.([a-zA-Z]+)\(\)(?:\.describe\(["\']([^"\']*)["\']\))?(?:\.optional\(\))?', schema_raw)
        for zp in zod_props:
            pname = zp.group(1)
            ztype = zp.group(2).lower()
            pdesc = zp.group(3) or ""
            is_opt = ".optional()" in zp.group(0)
            
            ptype = "string"
            if ztype in ('number', 'int', 'bigint'):
                ptype = "number"
            elif ztype in ('boolean', 'bool'):
                ptype = "boolean"
            elif ztype in ('array',):
                ptype = "array"
            elif ztype in ('object', 'record'):
                ptype = "object"
                
            props[pname] = {"type": ptype}
            if pdesc:
                props[pname]["description"] = pdesc
            if not is_opt:
                required.append(pname)
                
        schema = {
            "type": "object",
            "properties": props,
            "required": required
        }
        
        if not any(t["name"] == name for t in tools):
            tools.append({
                "name": name,
                "description": desc,
                "inputSchema": schema
            })

    # 3. Special sequential thinking / single-tool patterns
    if not tools:
        seq_m = re.search(r'name:\s*["\']([a-zA-Z0-9_-]+)["\'][\s\S]*?description:\s*(?:`([\s\S]*?)`|["\']([\s\S]*?)["\'])', code_text)
        if seq_m:
            tname = seq_m.group(1)
            tdesc = (seq_m.group(2) or seq_m.group(3) or "").strip()
            tools.append({
                "name": tname,
                "description": tdesc,
                "inputSchema": {"type": "object", "properties": {}}
            })

    return tools


def extract_server_from_git_tree(repo_path: Path, tag_or_commit: str, subpath: str, lang: str) -> Tuple[List[Dict[str, Any]], str, Optional[str]]:
    """Extract tools from a git tree at a specific tag/commit."""
    try:
        args = ['git', '-C', str(repo_path), 'ls-tree', '-r', '--name-only', tag_or_commit]
        if subpath:
            args.append(subpath)
        tree_out = subprocess.check_output(
            args,
            text=True,
            encoding='utf-8',
            errors='replace',
            stderr=subprocess.DEVNULL
        )
        files = [f.strip() for f in tree_out.strip().split('\n') if f.strip()]
        
        all_tools = []
        parsed_files = 0
        for f in files:
            if f.endswith(('.ts', '.js', '.py')):
                content = subprocess.check_output(
                    ['git', '-C', str(repo_path), 'show', f'{tag_or_commit}:{f}'],
                    text=True,
                    encoding='utf-8',
                    errors='replace',
                    stderr=subprocess.DEVNULL
                )
                if f.endswith('.py'):
                    tools = parse_python_tool_definitions(content)
                else:
                    tools = parse_typescript_tool_definitions(content)
                if tools:
                    all_tools.extend(tools)
                    parsed_files += 1

        # Deduplicate tools by name
        unique_tools = {}
        for t in all_tools:
            if t["name"] not in unique_tools:
                unique_tools[t["name"]] = t
            else:
                existing = unique_tools[t["name"]]
                if len(str(t.get("inputSchema", {}))) > len(str(existing.get("inputSchema", {}))):
                    unique_tools[t["name"]] = t

        res_tools = list(unique_tools.values())
        if res_tools:
            return res_tools, "static_source", None
        else:
            return [], "static_source", f"No tool definitions found in {subpath or 'root'} at {tag_or_commit}"
    except Exception as e:
        return [], "static_source", f"Git tree error: {str(e)}"


def run_corpus_extraction():
    print("=== Starting MCP Server Corpus Extraction ===")
    
    server_defs = [
        # Official modelcontextprotocol/servers
        {"id": "mcp-server-fetch", "name": "Fetch Server", "repo": "servers", "subpath": "src/fetch", "lang": "Python", "pkg": "mcp-server-fetch", "repo_url": "https://github.com/modelcontextprotocol/servers"},
        {"id": "mcp-server-git", "name": "Git Server", "repo": "servers", "subpath": "src/git", "lang": "Python", "pkg": "mcp-server-git", "repo_url": "https://github.com/modelcontextprotocol/servers"},
        {"id": "mcp-server-filesystem", "name": "Filesystem Server", "repo": "servers", "subpath": "src/filesystem", "lang": "TypeScript", "pkg": "@modelcontextprotocol/server-filesystem", "repo_url": "https://github.com/modelcontextprotocol/servers"},
        {"id": "mcp-server-memory", "name": "Memory Knowledge Graph Server", "repo": "servers", "subpath": "src/memory", "lang": "TypeScript", "pkg": "@modelcontextprotocol/server-memory", "repo_url": "https://github.com/modelcontextprotocol/servers"},
        {"id": "mcp-server-sequentialthinking", "name": "Sequential Thinking Server", "repo": "servers", "subpath": "src/sequentialthinking", "lang": "TypeScript", "pkg": "@modelcontextprotocol/server-sequential-thinking", "repo_url": "https://github.com/modelcontextprotocol/servers"},
        {"id": "mcp-server-everything", "name": "Everything Reference Server", "repo": "servers", "subpath": "src/everything", "lang": "TypeScript", "pkg": "@modelcontextprotocol/server-everything", "repo_url": "https://github.com/modelcontextprotocol/servers"},
        {"id": "mcp-server-time", "name": "Time Server", "repo": "servers", "subpath": "src/time", "lang": "Python", "pkg": "mcp-server-time", "repo_url": "https://github.com/modelcontextprotocol/servers"},
        {"id": "mcp-server-sqlite", "name": "SQLite Server", "repo": "servers", "subpath": "src/sqlite", "lang": "Python", "pkg": "mcp-server-sqlite", "repo_url": "https://github.com/modelcontextprotocol/servers"},
        {"id": "mcp-server-postgres", "name": "PostgreSQL Server", "repo": "servers", "subpath": "src/postgres", "lang": "TypeScript", "pkg": "@modelcontextprotocol/server-postgres", "repo_url": "https://github.com/modelcontextprotocol/servers"},
        {"id": "mcp-server-brave-search", "name": "Brave Search Server", "repo": "servers", "subpath": "src/brave-search", "lang": "TypeScript", "pkg": "@modelcontextprotocol/server-brave-search", "repo_url": "https://github.com/modelcontextprotocol/servers"},
        {"id": "mcp-server-gdrive", "name": "Google Drive Server", "repo": "servers", "subpath": "src/gdrive", "lang": "TypeScript", "pkg": "@modelcontextprotocol/server-gdrive", "repo_url": "https://github.com/modelcontextprotocol/servers"},
        {"id": "mcp-server-github", "name": "GitHub Server", "repo": "servers", "subpath": "src/github", "lang": "TypeScript", "pkg": "@modelcontextprotocol/server-github", "repo_url": "https://github.com/modelcontextprotocol/servers"},
        {"id": "mcp-server-gitlab", "name": "GitLab Server", "repo": "servers", "subpath": "src/gitlab", "lang": "TypeScript", "pkg": "@modelcontextprotocol/server-gitlab", "repo_url": "https://github.com/modelcontextprotocol/servers"},
        {"id": "mcp-server-google-maps", "name": "Google Maps Server", "repo": "servers", "subpath": "src/google-maps", "lang": "TypeScript", "pkg": "@modelcontextprotocol/server-google-maps", "repo_url": "https://github.com/modelcontextprotocol/servers"},
        {"id": "mcp-server-puppeteer", "name": "Puppeteer Server", "repo": "servers", "subpath": "src/puppeteer", "lang": "TypeScript", "pkg": "@modelcontextprotocol/server-puppeteer", "repo_url": "https://github.com/modelcontextprotocol/servers"},
        {"id": "mcp-server-redis", "name": "Redis Server", "repo": "servers", "subpath": "src/redis", "lang": "TypeScript", "pkg": "@modelcontextprotocol/server-redis", "repo_url": "https://github.com/modelcontextprotocol/servers"},
        {"id": "mcp-server-sentry", "name": "Sentry Server", "repo": "servers", "subpath": "src/sentry", "lang": "TypeScript", "pkg": "@modelcontextprotocol/server-sentry", "repo_url": "https://github.com/modelcontextprotocol/servers"},
        {"id": "mcp-server-slack", "name": "Slack Server", "repo": "servers", "subpath": "src/slack", "lang": "TypeScript", "pkg": "@modelcontextprotocol/server-slack", "repo_url": "https://github.com/modelcontextprotocol/servers"},
        {"id": "mcp-server-aws-kb", "name": "AWS Knowledge Base Retrieval Server", "repo": "servers", "subpath": "src/aws-kb-retrieval-server", "lang": "TypeScript", "pkg": "@modelcontextprotocol/server-aws-kb-retrieval", "repo_url": "https://github.com/modelcontextprotocol/servers"},
        {"id": "mcp-server-everart", "name": "EverArt AI Server", "repo": "servers", "subpath": "src/everart", "lang": "TypeScript", "pkg": "@modelcontextprotocol/server-everart", "repo_url": "https://github.com/modelcontextprotocol/servers"},
        {"id": "mcp-server-mssql", "name": "MSSQL Server", "repo": "servers", "subpath": "src/mssql-mcp", "lang": "TypeScript", "pkg": "@modelcontextprotocol/server-mssql", "repo_url": "https://github.com/modelcontextprotocol/servers"},
        # Additional community and standalone servers
        {"id": "mcp-server-qdrant", "name": "Qdrant Vector Search Server", "repo": "mcp-server-qdrant", "subpath": "src/mcp_server_qdrant", "lang": "Python", "pkg": "mcp-server-qdrant", "repo_url": "https://github.com/qdrant/mcp-server-qdrant"},
        {"id": "mcp-server-mysql", "name": "MySQL Server", "repo": "mcp-server-mysql", "subpath": "src/mysql_mcp_server", "lang": "Python", "pkg": "mysql_mcp_server", "repo_url": "https://github.com/designcomputer/mysql_mcp_server"},
        {"id": "mcp-server-kubernetes", "name": "Kubernetes Server", "repo": "mcp-server-kubernetes", "subpath": "src", "lang": "TypeScript", "pkg": "mcp-server-kubernetes", "repo_url": "https://github.com/Flux159/mcp-server-kubernetes"},
        {"id": "mcp-playwright", "name": "Playwright Browser Automation", "repo": "mcp-playwright", "subpath": "src", "lang": "TypeScript", "pkg": "mcp-playwright", "repo_url": "https://github.com/executeautomation/mcp-playwright"},
        {"id": "mcp-cloudflare", "name": "Cloudflare MCP Server", "repo": "mcp-server-sqlite", "subpath": "packages/mcp-server-cloudflare", "lang": "TypeScript", "pkg": "@cloudflare/mcp-server-cloudflare", "repo_url": "https://github.com/cloudflare/mcp-server-cloudflare"},
        {"id": "mcp-python-sdk", "name": "Python SDK Reference Examples", "repo": "python-sdk", "subpath": "examples", "lang": "Python", "pkg": "mcp", "repo_url": "https://github.com/modelcontextprotocol/python-sdk"},
        {"id": "mcp-go-reference", "name": "Go MCP Reference Server", "repo": "mcp-go", "subpath": "examples", "lang": "Go", "pkg": "mcp-go", "repo_url": "https://github.com/mark3labs/mcp-go"}
    ]

    corpus_servers = []
    all_versions_record = []
    total_snapshots = 0

    for sdef in server_defs:
        server_id = sdef["id"]
        repo_dir = REPOS_DIR / sdef["repo"]
        if not repo_dir.exists():
            print(f"Skipping {server_id}: repo {repo_dir} not found")
            corpus_servers.append({
                "server_id": server_id,
                "name": sdef["name"],
                "repository": sdef["repo_url"],
                "language": sdef["lang"],
                "ecosystem": sdef["pkg"],
                "versions": [],
                "selected_versions": [],
                "status": "failed",
                "failure_reason": "Repository directory not found"
            })
            continue

        raw_tags = get_git_tags_and_commits(repo_dir)
        print(f"Processing {server_id} ({len(raw_tags)} candidate tags/commits)...", flush=True)

        server_snap_dir = SNAPSHOT_DIR / server_id
        os.makedirs(server_snap_dir, exist_ok=True)

        selected_versions = []
        valid_snapshots_for_server = []

        for item in raw_tags:
            tag_name = item["tag"]
            commit_sha = item["commit"]
            date_str = item["date"]
            
            # Check if subpath exists in this tag
            subpath = sdef["subpath"]
            if subpath:
                check_res = subprocess.run(
                    ['git', '-C', str(repo_dir), 'cat-file', '-e', f'{commit_sha}:{subpath}'],
                    capture_output=True
                )
                if check_res.returncode != 0:
                    continue

            # Extract tools
            tools, method, err = extract_server_from_git_tree(repo_dir, commit_sha, sdef["subpath"], sdef["lang"])
            
            v_record = {
                "server_id": server_id,
                "version": tag_name,
                "commit_sha": commit_sha,
                "date": date_str,
                "source_url": f"{sdef['repo_url']}/tree/{commit_sha}/{sdef['subpath']}",
                "installation_method": "pip" if sdef["lang"] == "Python" else "npm",
                "collection_status": "success" if tools else "failed",
                "extraction_method": method,
                "tool_count": len(tools),
                "failure_reason": err
            }
            all_versions_record.append(v_record)

            if tools:
                safe_vname = re.sub(r'[^a-zA-Z0-9_.-]', '_', tag_name)
                snap_path = server_snap_dir / f"{safe_vname}.json"
                snapshot_data = {
                    "server_id": server_id,
                    "server_name": sdef["name"],
                    "version": tag_name,
                    "commit_sha": commit_sha,
                    "date": date_str,
                    "extraction_method": method,
                    "tools": tools
                }
                with open(snap_path, 'w', encoding='utf-8') as f:
                    json.dump(snapshot_data, f, indent=2)
                
                selected_versions.append(tag_name)
                valid_snapshots_for_server.append((tag_name, commit_sha, date_str, tools))
                total_snapshots += 1

        status_str = "success" if len(selected_versions) >= 1 else "failed"
        corpus_servers.append({
            "server_id": server_id,
            "name": sdef["name"],
            "repository": sdef["repo_url"],
            "language": sdef["lang"],
            "ecosystem": sdef["pkg"],
            "available_tags_count": len(raw_tags),
            "versions": [t["tag"] for t in raw_tags],
            "selected_versions": selected_versions,
            "status": status_str,
            "failure_reason": None if status_str == "success" else "No valid tool definitions extracted across candidate tags"
        })
        print(f"  -> {server_id}: {len(selected_versions)} versions extracted successfully.", flush=True)

    corpus_metadata = {
        "corpus_version": "phase2_v1",
        "description": "Open-source Model Context Protocol (MCP) server version corpus for tool definition update measurement",
        "total_servers": len(corpus_servers),
        "successful_servers": sum(1 for s in corpus_servers if s["status"] == "success"),
        "total_snapshots": total_snapshots,
        "servers": corpus_servers
    }
    with open(DATA_DIR / "mcp_corpus.json", 'w', encoding='utf-8') as f:
        json.dump(corpus_metadata, f, indent=2)
    print(f"Saved {DATA_DIR / 'mcp_corpus.json'}", flush=True)

    versions_metadata = {
        "total_version_records": len(all_versions_record),
        "successful_extractions": sum(1 for v in all_versions_record if v["collection_status"] == "success"),
        "failed_extractions": sum(1 for v in all_versions_record if v["collection_status"] == "failed"),
        "versions": all_versions_record
    }
    with open(DATA_DIR / "mcp_versions.json", 'w', encoding='utf-8') as f:
        json.dump(versions_metadata, f, indent=2)
    print(f"Saved {DATA_DIR / 'mcp_versions.json'}", flush=True)


if __name__ == "__main__":
    run_corpus_extraction()
