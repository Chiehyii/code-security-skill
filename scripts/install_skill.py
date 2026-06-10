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
  codex        OpenAI Codex   → .codex/config.toml  +  AGENTS.md
  antigravity  Antigravity    → ~/.gemini/config/mcp_config.json (global)
  all          All of the above (default)

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

ALL_PLATFORMS = ["claude", "cursor", "copilot", "windsurf", "codex", "antigravity"]

PLATFORM_LABELS = {
    "claude":      "Claude Code    → .mcp.json  +  CLAUDE.md",
    "cursor":      "Cursor         → .cursor/mcp.json  +  .cursor/rules/code-security.mdc",
    "copilot":     "GitHub Copilot → .github/copilot-instructions.md",
    "windsurf":    "Windsurf       → .windsurf/mcp_config.json  +  .windsurf/rules/code-security.md",
    "codex":       "OpenAI Codex   → .codex/config.toml  +  AGENTS.md",
    "antigravity": "Antigravity    → ~/.gemini/config/mcp_config.json  (global)",
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


def _write_mcp_toml(config_path: Path, server_py: Path, force: bool) -> str:
    """Write / merge a [mcp_servers.code-security] section into a TOML config file."""
    section_header = "[mcp_servers.code-security]"
    new_section = (
        f"\n{section_header}\n"
        f'command = "{sys.executable}"\n'
        f'args    = ["{server_py.as_posix()}"]\n'
    )
    if config_path.exists():
        existing = config_path.read_text(encoding="utf-8")
        if section_header in existing:
            if not force:
                return f"  --  already present    {config_path}"
            import re as _re
            existing = _re.sub(
                rf"\n?\[mcp_servers\.code-security\][^\[]*",
                "",
                existing,
                flags=_re.DOTALL,
            )
        config_path.write_text(existing + new_section, encoding="utf-8")
        return f"  ok  mcp config          {config_path}"
    else:
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(new_section.lstrip(), encoding="utf-8")
        return f"  ok  mcp config          {config_path}"


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
    results = []
    # MCP config — .codex/config.toml (project) or ~/.codex/config.toml (global)
    results += _ensure_global_server(force)
    results.append(_write_mcp_toml(
        target / ".codex" / "config.toml",
        GLOBAL_DIR / "mcp_server.py",
        force,
    ))
    # Static rules — AGENTS.md
    results.append(_inject_or_replace(target / "AGENTS.md", _skill_content(), force))
    return results


def install_antigravity(target: Path, force: bool) -> list:
    # MCP config is global — written to ~/.gemini/config/mcp_config.json
    # (Antigravity has no project-level rules file)
    results = []
    results += _ensure_global_server(force)
    global_cfg = Path.home() / ".gemini" / "config" / "mcp_config.json"
    results.append(_write_mcp_json(global_cfg, GLOBAL_DIR / "mcp_server.py", force))
    results.append("  --  note: config is global, applies to all projects")
    return results


INSTALLERS = {
    "claude":      install_claude,
    "cursor":      install_cursor,
    "copilot":     install_copilot,
    "windsurf":    install_windsurf,
    "codex":       install_codex,
    "antigravity": install_antigravity,
}


# ---------------------------------------------------------------------------
# Uninstall helpers
# ---------------------------------------------------------------------------

def _remove_block(file_path: Path) -> str:
    """Remove the injected skill block from a markdown file."""
    if not file_path.exists():
        return f"  --  not found          {file_path}"
    content = file_path.read_text(encoding="utf-8")
    if _BLOCK_START not in content:
        return f"  --  not present        {file_path}"
    new_content = re.sub(
        rf"\n?{re.escape(_BLOCK_START)}.*?{re.escape(_BLOCK_END)}\n?",
        "",
        content,
        flags=re.DOTALL,
    )
    if new_content.strip():
        file_path.write_text(new_content, encoding="utf-8")
        return f"  ok  removed block      {file_path}"
    else:
        file_path.unlink()
        return f"  ok  deleted (empty)    {file_path}"


def _remove_file(file_path: Path) -> str:
    if not file_path.exists():
        return f"  --  not found          {file_path}"
    file_path.unlink()
    return f"  ok  deleted            {file_path}"


def _remove_mcp_json_entry(config_path: Path) -> str:
    if not config_path.exists():
        return f"  --  not found          {config_path}"
    try:
        cfg = json.loads(config_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return f"  !!  invalid JSON       {config_path}"
    servers = cfg.get("mcpServers", {})
    if "code-security" not in servers:
        return f"  --  not present        {config_path}"
    del servers["code-security"]
    if not servers:
        del cfg["mcpServers"]
    if not cfg:
        config_path.unlink()
        return f"  ok  deleted (empty)    {config_path}"
    config_path.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    return f"  ok  removed entry      {config_path}"


def _remove_mcp_toml_entry(config_path: Path) -> str:
    if not config_path.exists():
        return f"  --  not found          {config_path}"
    content = config_path.read_text(encoding="utf-8")
    if "[mcp_servers.code-security]" not in content:
        return f"  --  not present        {config_path}"
    # Walk line-by-line: drop the target section and all its key-value lines
    result, in_section = [], False
    for line in content.splitlines(keepends=True):
        stripped = line.strip()
        if stripped == "[mcp_servers.code-security]":
            in_section = True
            continue
        if in_section and stripped.startswith("["):
            in_section = False  # new section header ends this block
        if not in_section:
            result.append(line)
    new_content = "".join(result)
    if new_content.strip():
        config_path.write_text(new_content, encoding="utf-8")
    else:
        config_path.unlink()
    return f"  ok  removed entry      {config_path}"


# ---------------------------------------------------------------------------
# Platform uninstallers
# ---------------------------------------------------------------------------

def uninstall_claude(target: Path) -> list:
    results = []
    dest = target / ".claude" / "skills" / "code-security"
    if dest.exists():
        shutil.rmtree(dest)
        results.append(f"  ok  deleted            {dest}")
    else:
        results.append(f"  --  not found          {dest}")
    results.append(_remove_mcp_json_entry(target / ".mcp.json"))
    results.append(_remove_block(target / "CLAUDE.md"))
    return results


def uninstall_cursor(target: Path) -> list:
    return [
        _remove_file(target / ".cursor" / "rules" / "code-security.mdc"),
        _remove_mcp_json_entry(target / ".cursor" / "mcp.json"),
    ]


def uninstall_copilot(target: Path) -> list:
    return [_remove_block(target / ".github" / "copilot-instructions.md")]


def uninstall_windsurf(target: Path) -> list:
    return [
        _remove_file(target / ".windsurf" / "rules" / "code-security.md"),
        _remove_mcp_json_entry(target / ".windsurf" / "mcp_config.json"),
    ]


def uninstall_codex(target: Path) -> list:
    return [
        _remove_mcp_toml_entry(target / ".codex" / "config.toml"),
        _remove_block(target / "AGENTS.md"),
    ]


def uninstall_antigravity(target: Path) -> list:
    global_cfg = Path.home() / ".gemini" / "config" / "mcp_config.json"
    return [
        _remove_mcp_json_entry(global_cfg),
        "  --  note: global config updated",
    ]


UNINSTALLERS = {
    "claude":      uninstall_claude,
    "cursor":      uninstall_cursor,
    "copilot":     uninstall_copilot,
    "windsurf":    uninstall_windsurf,
    "codex":       uninstall_codex,
    "antigravity": uninstall_antigravity,
}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_platforms(ai_list: list) -> list:
    requested = [p.lower() for p in ai_list]
    invalid   = [p for p in requested if p not in ALL_PLATFORMS + ["all"]]
    if invalid:
        print(f"Error: Unknown platform(s): {', '.join(invalid)}\n"
              f"Valid: {', '.join(ALL_PLATFORMS + ['all'])}", file=sys.stderr)
        sys.exit(1)
    return ALL_PLATFORMS if "all" in requested else list(dict.fromkeys(requested))


def _resolve_target(path_str: str) -> Path:
    target = Path(path_str).resolve()
    if not target.is_dir():
        print(f"Error: '{target}' is not a directory.", file=sys.stderr)
        sys.exit(1)
    if target == ROOT:
        print("Error: Cannot operate on this source repository.", file=sys.stderr)
        sys.exit(1)
    return target


def cmd_install(args):
    platforms = _parse_platforms(args.ai)
    target    = _resolve_target(args.target_project)

    print()
    print("  Code Security Skill - Install")
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
    mcp_platforms = [p for p in platforms if p in ("claude", "cursor", "windsurf", "codex", "antigravity")]
    if mcp_platforms:
        print("  MCP server ready:")
        print(f"    {GLOBAL_DIR / 'mcp_server.py'}")
        print()
        print("  Prerequisite (if not installed):  pip install mcp")
        print()


def cmd_uninstall(args):
    platforms   = _parse_platforms(args.ai)
    target      = _resolve_target(args.target_project)
    remove_global = args.global_server

    print()
    print("  Code Security Skill - Uninstall")
    print(f"  Target   : {target}")
    print(f"  Platforms: {', '.join(platforms)}")
    print()

    for platform in platforms:
        print(f"  [{platform.upper()}] {PLATFORM_LABELS[platform]}")
        for line in UNINSTALLERS[platform](target):
            print(line)
        print()

    if remove_global:
        if GLOBAL_DIR.exists():
            shutil.rmtree(GLOBAL_DIR)
            print(f"  ok  deleted global server  {GLOBAL_DIR}")
        else:
            print(f"  --  not found              {GLOBAL_DIR}")
        print()

    print("  Done.")
    print()


def main():
    _configure_output()

    parser = argparse.ArgumentParser(
        description="Code Security Skill — install or uninstall",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command")

    # ── install ──────────────────────────────────────────────────────────────
    p_install = sub.add_parser("install", help="Install the skill into a project")
    p_install.add_argument("target_project", nargs="?", default=".")
    p_install.add_argument("--ai", nargs="+", default=["all"], metavar="PLATFORM")
    p_install.add_argument("--force", action="store_true")

    # ── uninstall ─────────────────────────────────────────────────────────────
    p_uninst = sub.add_parser("uninstall", help="Remove the skill from a project")
    p_uninst.add_argument("target_project", nargs="?", default=".")
    p_uninst.add_argument("--ai", nargs="+", default=["all"], metavar="PLATFORM")
    p_uninst.add_argument("--global-server", action="store_true",
                          help=f"Also delete the global MCP server at {GLOBAL_DIR}")

    args = parser.parse_args()

    if args.command == "install":
        cmd_install(args)
    elif args.command == "uninstall":
        cmd_uninstall(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
