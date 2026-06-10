#!/usr/bin/env python3
"""Install the Code Security Skill into a project for one or more AI coding tools.

What gets installed
-------------------
For every platform:
  1. Static skill rules injected into the tool's config file  (always-on, no network)
  2. MCP server config  →  AI can call search_security() at runtime for live queries

MCP server lives at:  ~/.code-security-skill/  (installed once, shared across projects)
Prerequisite for MCP: pip install mcp

Supported platforms
-------------------
  claude    Claude Code  → .mcp.json  +  CLAUDE.md
  cursor    Cursor       → .cursor/mcp.json  +  .cursor/rules/code-security.mdc
  windsurf  Windsurf     → .windsurf/mcp_config.json  +  .windsurf/rules/code-security.md
  copilot   GitHub Copilot → .github/copilot-instructions.md  (no MCP yet)
  codex     OpenAI Codex → AGENTS.md  (no MCP yet)
  all       All of the above (default)

Usage
-----
  python3 scripts/install_skill.py                        # all platforms, cwd
  python3 scripts/install_skill.py /path/to/project       # all platforms, target dir
  python3 scripts/install_skill.py . --ai claude          # Claude Code only
  python3 scripts/install_skill.py . --ai cursor copilot  # Cursor + Copilot
  python3 scripts/install_skill.py . --force              # overwrite existing files
"""

import argparse
import json
import re
import shutil
import sys
import textwrap
from pathlib import Path

ROOT      = Path(__file__).resolve().parents[1]
SOURCE    = ROOT / "src" / "code-security"
TEMPLATES = SOURCE / "templates"

# Global install directory for the MCP server
GLOBAL_DIR = Path.home() / ".code-security-skill"

ALL_PLATFORMS = ["claude", "cursor", "copilot", "windsurf", "codex"]

PLATFORM_LABELS = {
    "claude":   "Claude Code    → .mcp.json  +  CLAUDE.md",
    "cursor":   "Cursor         → .cursor/mcp.json  +  .cursor/rules/code-security.mdc",
    "copilot":  "GitHub Copilot → .github/copilot-instructions.md",
    "windsurf": "Windsurf       → .windsurf/mcp_config.json  +  .windsurf/rules/code-security.md",
    "codex":    "OpenAI Codex   → AGENTS.md",
}

_BLOCK_START = "<!-- code-security-skill-start -->"
_BLOCK_END   = "<!-- code-security-skill-end -->"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _configure_output():
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")


def _skill_content() -> str:
    return (TEMPLATES / "skill-content.md").read_text(encoding="utf-8")


def _inject_or_replace(file_path: Path, block: str, force: bool) -> str:
    new_section = f"\n{_BLOCK_START}\n{block}\n{_BLOCK_END}\n"
    if file_path.exists():
        existing = file_path.read_text(encoding="utf-8")
        if _BLOCK_START in existing:
            if not force:
                return f"  --  already present    {file_path}"
            existing = re.sub(
                rf"\n?{re.escape(_BLOCK_START)}.*?{re.escape(_BLOCK_END)}\n?",
                "",
                existing,
                flags=re.DOTALL,
            )
        file_path.write_text(existing + new_section, encoding="utf-8")
        return f"  ok  updated            {file_path}"
    else:
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(new_section, encoding="utf-8")
        return f"  ok  created            {file_path}"


def _overwrite_file(file_path: Path, content: str, force: bool) -> str:
    if file_path.exists() and not force:
        return f"  --  already exists     {file_path}"
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_text(content, encoding="utf-8")
    verb = "updated" if file_path.exists() else "created"
    return f"  ok  {verb:<14} {file_path}"


def _write_mcp_json(config_path: Path, server_py: Path, force: bool) -> str:
    """Write / merge an mcpServers entry into a JSON config file."""
    entry = {
        "command": sys.executable,
        "args": [str(server_py)],
    }
    if config_path.exists():
        try:
            cfg = json.loads(config_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            cfg = {}
        servers = cfg.setdefault("mcpServers", {})
        if "code-security" in servers and not force:
            return f"  --  already present    {config_path}"
        servers["code-security"] = entry
    else:
        config_path.parent.mkdir(parents=True, exist_ok=True)
        cfg = {"mcpServers": {"code-security": entry}}
    config_path.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    return f"  ok  mcp config          {config_path}"


# ---------------------------------------------------------------------------
# Global server install  (~/.code-security-skill/)
# ---------------------------------------------------------------------------

def _ensure_global_server(force: bool) -> list:
    results = []
    if GLOBAL_DIR.exists():
        if force:
            shutil.rmtree(GLOBAL_DIR)
            results.append(f"  ok  removed old server  {GLOBAL_DIR}")
        else:
            return [f"  --  server exists      {GLOBAL_DIR}"]
    shutil.copytree(
        SOURCE, GLOBAL_DIR,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".pytest_cache"),
    )
    results.append(f"  ok  installed server    {GLOBAL_DIR}")
    return results


# ---------------------------------------------------------------------------
# Platform installers
# ---------------------------------------------------------------------------

def install_claude(target: Path, force: bool) -> list:
    results = []

    # 1. Copy skill files for local search.py use
    dest = target / ".claude" / "skills" / "code-security"
    if dest.exists():
        if force:
            shutil.rmtree(dest)
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(SOURCE, dest, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
            results.append(f"  ok  replaced           {dest}")
        else:
            results.append(f"  --  already exists     {dest}")
    else:
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(SOURCE, dest, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        results.append(f"  ok  copied             {dest}")

    # 2. MCP config  (.mcp.json at project root)
    results += _ensure_global_server(force)
    results.append(_write_mcp_json(target / ".mcp.json", GLOBAL_DIR / "mcp_server.py", force))

    # 3. Inject static rules into CLAUDE.md
    block = textwrap.dedent("""\
        ## Code Security Skill

        MCP tool available: **search_security(query, mode, lang)**
        Call it before writing any security-sensitive code.

        Local search (also available):
        ```bash
        python3 .claude/skills/code-security/scripts/search.py "login" --lang python
        ```

        Full inline security instructions follow:

        """) + _skill_content()
    results.append(_inject_or_replace(target / "CLAUDE.md", block, force))
    return results


def install_cursor(target: Path, force: bool) -> list:
    results = []

    # 1. MCP config  (.cursor/mcp.json)
    results += _ensure_global_server(force)
    results.append(_write_mcp_json(target / ".cursor" / "mcp.json", GLOBAL_DIR / "mcp_server.py", force))

    # 2. Static rules  (.cursor/rules/code-security.mdc)
    frontmatter = textwrap.dedent("""\
        ---
        description: Automatically apply OWASP security standards when writing or reviewing code
        globs: "**/*.{py,js,ts,jsx,tsx,java,go,rb,php,cs,c,cpp,rs,swift,kt,tf}"
        alwaysApply: true
        ---

        """)
    results.append(_overwrite_file(
        target / ".cursor" / "rules" / "code-security.mdc",
        frontmatter + _skill_content(),
        force,
    ))
    return results


def install_windsurf(target: Path, force: bool) -> list:
    results = []

    # 1. MCP config  (.windsurf/mcp_config.json)
    results += _ensure_global_server(force)
    results.append(_write_mcp_json(
        target / ".windsurf" / "mcp_config.json",
        GLOBAL_DIR / "mcp_server.py",
        force,
    ))

    # 2. Static rules  (.windsurf/rules/code-security.md)
    frontmatter = textwrap.dedent("""\
        ---
        trigger: always_on
        description: Automatically apply OWASP security standards when writing or reviewing code
        ---

        """)
    results.append(_overwrite_file(
        target / ".windsurf" / "rules" / "code-security.md",
        frontmatter + _skill_content(),
        force,
    ))
    return results


def install_copilot(target: Path, force: bool) -> list:
    # GitHub Copilot does not yet support project-level MCP — static rules only
    return [_inject_or_replace(
        target / ".github" / "copilot-instructions.md",
        _skill_content(),
        force,
    )]


def install_codex(target: Path, force: bool) -> list:
    # OpenAI Codex CLI does not yet support MCP — static rules only
    return [_inject_or_replace(target / "AGENTS.md", _skill_content(), force)]


INSTALLERS = {
    "claude":   install_claude,
    "cursor":   install_cursor,
    "copilot":  install_copilot,
    "windsurf": install_windsurf,
    "codex":    install_codex,
}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    _configure_output()
    parser = argparse.ArgumentParser(
        description="Install the Code Security Skill (static rules + MCP server)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            examples:
              python3 scripts/install_skill.py                         # all platforms, cwd
              python3 scripts/install_skill.py /path/to/project        # all platforms, target dir
              python3 scripts/install_skill.py . --ai claude           # Claude Code only
              python3 scripts/install_skill.py . --ai cursor windsurf  # Cursor + Windsurf
              python3 scripts/install_skill.py . --force               # overwrite existing
        """),
    )
    parser.add_argument("target_project", nargs="?", default=".",
                        help="Target project directory (default: current directory)")
    parser.add_argument("--ai", nargs="+", default=["all"], metavar="PLATFORM",
                        help=f"Platforms: {', '.join(ALL_PLATFORMS)}, all (default: all)")
    parser.add_argument("--force", action="store_true",
                        help="Overwrite or update existing files")
    args = parser.parse_args()

    requested = [p.lower() for p in args.ai]
    invalid   = [p for p in requested if p not in ALL_PLATFORMS + ["all"]]
    if invalid:
        parser.error(f"Unknown platform(s): {', '.join(invalid)}\n"
                     f"Valid: {', '.join(ALL_PLATFORMS + ['all'])}")
    platforms = ALL_PLATFORMS if "all" in requested else list(dict.fromkeys(requested))

    target = Path(args.target_project).resolve()
    if not target.is_dir():
        print(f"Error: '{target}' is not a directory.", file=sys.stderr)
        sys.exit(1)
    if target == ROOT:
        print("Error: Cannot install into this source repository.", file=sys.stderr)
        sys.exit(1)

    print()
    print("  Code Security Skill - Installer")
    print(f"  Target   : {target}")
    print(f"  Platforms: {', '.join(platforms)}")
    print()

    for platform in platforms:
        print(f"  [{platform.upper()}] {PLATFORM_LABELS[platform]}")
        for line in INSTALLERS[platform](target, args.force):
            print(line)
        print()

    print("  Done. The skill auto-activates when writing security-sensitive code.")
    print()

    mcp_platforms = [p for p in platforms if p in ("claude", "cursor", "windsurf")]
    if mcp_platforms:
        print("  MCP server ready:")
        print(f"    {GLOBAL_DIR / 'mcp_server.py'}")
        print()
        print("  Prerequisite (if not installed):")
        print("    pip install mcp")
        print()

    if "claude" in platforms:
        print("  Verify search engine:")
        print("    python3 .claude/skills/code-security/scripts/search.py 'login' --lang python")
        print()


if __name__ == "__main__":
    main()
