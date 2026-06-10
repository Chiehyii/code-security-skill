#!/usr/bin/env python3
"""
Code Security Skill — MCP Server

Exposes the security knowledge base as MCP tools so AI coding tools
(Claude Code, Cursor, Windsurf) can query it at runtime.

Start command (for MCP config):
    python3 ~/.code-security-skill/mcp_server.py

Install the 'mcp' package first:
    pip install mcp
"""

import asyncio
import subprocess
import sys
from pathlib import Path

try:
    import mcp.server.stdio
    import mcp.types as types
    from mcp.server import Server, NotificationOptions
    from mcp.server.models import InitializationOptions
except ImportError:
    print(
        "Error: the 'mcp' package is required.\n"
        "  pip install mcp",
        file=sys.stderr,
    )
    sys.exit(1)

HERE          = Path(__file__).resolve().parent
SEARCH_SCRIPT = HERE / "scripts" / "search.py"

server = Server("code-security-skill")


def _run_search(query: str, mode: str = "all", lang: str | None = None) -> str:
    cmd = [sys.executable, str(SEARCH_SCRIPT), query, "--mode", mode]
    if lang:
        cmd += ["--lang", lang]
    r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    return (r.stdout or "").strip() or r.stderr.strip() or "No results found."


@server.list_tools()
async def list_tools() -> list[types.Tool]:
    return [
        types.Tool(
            name="search_security",
            description=(
                "Search the Code Security knowledge base.\n\n"
                "Returns: vulnerability profiles (OWASP Top 10 2025 / API / LLM), "
                "feature security checklists, language-specific secure engineering rules, "
                "cryptography guides, OWASP ASVS 5.0.0 chapters, MITRE CWE Top 25 2025, "
                "and governed assurance controls.\n\n"
                "IMPORTANT: Call this tool BEFORE writing any security-sensitive code "
                "(auth, database, file upload, API, payment, session, etc.)."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": (
                            "Feature or topic to look up. "
                            "Examples: 'login authentication', 'file upload', "
                            "'sql injection', 'jwt token', 'password hashing', "
                            "'api endpoint', 'llm prompt injection'"
                        ),
                    },
                    "mode": {
                        "type": "string",
                        "enum": [
                            "all", "checklist", "vuln", "crypto",
                            "rules", "asvs", "cwe", "control",
                        ],
                        "default": "all",
                        "description": (
                            "all       = full report (default)\n"
                            "checklist = feature security checklist\n"
                            "vuln      = vulnerability profiles (OWASP)\n"
                            "crypto    = cryptography guide\n"
                            "rules     = language-specific rules\n"
                            "asvs      = OWASP ASVS 5.0.0 chapters\n"
                            "cwe       = MITRE CWE Top 25 root causes\n"
                            "control   = assurance controls (SAST/DAST/SBOM/…)"
                        ),
                    },
                    "lang": {
                        "type": "string",
                        "enum": [
                            "python", "javascript", "typescript", "java",
                            "go", "php", "ruby", "csharp", "cpp", "rust", "terraform",
                        ],
                        "description": (
                            "Programming language for language-specific rules. "
                            "Optional — omit for generic guidance."
                        ),
                    },
                },
                "required": ["query"],
            },
        )
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:
    if name != "search_security":
        raise ValueError(f"Unknown tool: {name}")

    query = arguments.get("query", "")
    mode  = arguments.get("mode", "all")
    lang  = arguments.get("lang")

    loop   = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, _run_search, query, mode, lang)

    return [types.TextContent(type="text", text=result)]


async def _main():
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="code-security-skill",
                server_version="3.0.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )


if __name__ == "__main__":
    asyncio.run(_main())
