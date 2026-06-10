# Code Security Skill

[![License: MIT](https://img.shields.io/badge/license-MIT-green?style=for-the-badge)](package.json)
[![OWASP Top 10](https://img.shields.io/badge/OWASP_Top_10-2025-red?style=for-the-badge)](https://owasp.org/Top10/2025/en/)
[![Vulnerability Profiles](https://img.shields.io/badge/vulnerability_profiles-50-orange?style=for-the-badge)](src/code-security/data/vulnerabilities.csv)
[![Python 3](https://img.shields.io/badge/python-3.x-yellow?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)

Code Security Skill is a security knowledge base and MCP server for AI coding
assistants. It gives supported assistants always-on secure-coding instructions
and lets them retrieve feature-specific security guidance before writing or
reviewing security-sensitive code.

It is a secure-development aid, not a vulnerability scanner. Use it together
with threat modeling, code review, tests, SAST, DAST, dependency scanning,
secret scanning, and expert security review.

## How It Works

```text
Developer asks an AI assistant to build or review a feature
                         |
                         v
        Always-on static security instructions are loaded
                         |
                         v
       AI calls the MCP tool search_security when appropriate
                         |
                         v
      MCP server searches the versioned CSV knowledge base
                         |
                         v
 AI applies relevant checklists, vulnerability guidance, and rules
```

The project provides two complementary layers:

1. **Static rules**: platform-specific instruction files that remind the AI to
   apply secure-development practices and query the knowledge base.
2. **MCP retrieval**: a local stdio MCP server exposing
   `search_security(query, mode, lang)` for topic-specific guidance.

The MCP server retrieves guidance. It does not automatically scan source code,
prove that generated code is secure, or replace security testing tools.

## Knowledge Base

`src/code-security` is the repository's single source of truth.

| Dataset | Coverage |
|---|---:|
| Vulnerability profiles | 50 |
| Feature security checklists | 26 |
| Language, framework, and engineering rules | 51 |
| Cryptography guides | 12 |
| OWASP ASVS 5.0.0 chapter index | 17 chapters / 345 requirements |
| MITRE CWE Top 25 2025 | 25 ranked weaknesses |
| Extended CWE mappings | SSTI (`CWE-1336`) and NoSQL Injection (`CWE-943`) |
| Governed assurance controls | 15 |

The validation script verifies complete category coverage for:

- OWASP Web Application Top 10 2025
- OWASP API Security Top 10 2023
- OWASP Top 10 for LLM Applications 2025
- OWASP ASVS 5.0.0 chapter totals
- MITRE CWE Top 25 2025

The vulnerability profiles also include Server-Side Template Injection (SSTI),
NoSQL Injection, supply-chain failures, cloud and container
misconfiguration, API authorization failures, and LLM-specific risks.

## Supported AI Tools

| Tool | Static rules | MCP configuration |
|---|---|---|
| Claude Code | `CLAUDE.md` and local skill copy | `.mcp.json` |
| Cursor | `.cursor/rules/code-security.mdc` | `.cursor/mcp.json` |
| GitHub Copilot in VS Code | `.github/copilot-instructions.md` | `.vscode/mcp.json` |
| Windsurf | `.windsurf/rules/code-security.md` | `.windsurf/mcp_config.json` |
| OpenAI Codex | `AGENTS.md` | `.codex/config.toml` |
| Antigravity | `GEMINI.md` | `~/.gemini/config/mcp_config.json` |

The installer copies the shared MCP server and knowledge base to
`~/.code-security-skill/`. Platform configuration files then start that local
server with the Python interpreter used during installation.

Generated project files are intentionally not committed to this source
repository.

## Prerequisites

- Python 3
- The Python `mcp` package for runtime MCP queries
- Node.js 14 or later only when using the npm CLI
- Git only when installing directly from the repository

Install the MCP runtime dependency:

```bash
python -m pip install mcp
```

Optional MIME type validation support:

```bash
python -m pip install python-magic
```

On systems where the interpreter command is `python3`, replace `python` with
`python3` in the examples below. On Windows, `py -3` may also be used.

## Installation

Run installation commands from the root of the **target project**, not from
this source repository. The installer intentionally refuses to install into
the source repository to avoid generating duplicate knowledge-base copies.

### npm CLI

After the `codesecurity` package is published or installed from a local
package, initialize the current project:

```bash
npm install -g codesecurity
cd /path/to/your-project
codesecurity init
```

Install only selected integrations:

```bash
codesecurity init --ai claude
codesecurity init --ai cursor copilot codex
codesecurity init --ai antigravity
```

Refresh existing generated files and MCP entries:

```bash
codesecurity init --force
```

### Directly From This Repository

```bash
git clone --depth 1 https://github.com/Chiehyii/code-security-skill.git
cd /path/to/your-project
python /path/to/code-security-skill/scripts/install_skill.py install .
```

Install selected integrations:

```bash
python /path/to/code-security-skill/scripts/install_skill.py install . --ai claude
python /path/to/code-security-skill/scripts/install_skill.py install . --ai cursor copilot
python /path/to/code-security-skill/scripts/install_skill.py install . --force
```

Valid `--ai` values are `claude`, `cursor`, `copilot`, `windsurf`, `codex`,
`antigravity`, and `all`. The default is `all`.

### Uninstall

Using the npm CLI:

```bash
codesecurity uninstall
codesecurity uninstall --ai cursor copilot
codesecurity uninstall --global-server
```

Using the Python installer:

```bash
python /path/to/code-security-skill/scripts/install_skill.py uninstall .
python /path/to/code-security-skill/scripts/install_skill.py uninstall . --ai codex
python /path/to/code-security-skill/scripts/install_skill.py uninstall . --global-server
```

`--global-server` also removes the shared `~/.code-security-skill/` directory.
Do not use it while another project still relies on that shared MCP server.

## Usage

After installation, restart or reload the AI tool so it discovers the new
rules and MCP configuration. Then request normal development or review work:

```text
Build a login system with secure session management.
Create an API endpoint for updating user profiles.
Review this file-upload handler for security issues.
Implement a password-reset flow.
Check this MongoDB query for NoSQL injection.
```

The static rules instruct the AI to call `search_security` before handling
security-sensitive features. A typical MCP request looks like:

```json
{
  "query": "login authentication session",
  "mode": "all",
  "lang": "python"
}
```

Available modes:

| Mode | Result |
|---|---|
| `all` | Combined security report |
| `checklist` | Feature-specific implementation checklist |
| `vuln` | Vulnerability profiles and fix patterns |
| `rules` | Language-specific secure-coding rules |
| `crypto` | Cryptography recommendations |
| `asvs` | OWASP ASVS verification areas |
| `cwe` | CWE root causes |
| `control` | Assurance controls such as SAST, DAST, SBOM, and fuzzing |

### Manual Knowledge-Base Search

The same search engine can be used without an MCP client:

```bash
# Combined report
python src/code-security/scripts/search.py "login authentication" --lang python

# Focused searches
python src/code-security/scripts/search.py "file upload" --mode checklist
python src/code-security/scripts/search.py "sql injection" --mode vuln
python src/code-security/scripts/search.py "password hashing" --mode crypto
python src/code-security/scripts/search.py "database query" --mode rules --lang javascript
python src/code-security/scripts/search.py "authentication" --mode asvs
python src/code-security/scripts/search.py "memory buffer" --mode cwe
python src/code-security/scripts/search.py "sast sbom secret scanning" --mode control
```

Search results are ranked using a BM25 and keyword hybrid search. Common
Traditional Chinese security queries are supported.

## Validation and Tests

Validate all CSV schemas, required standards coverage, ASVS totals, CWE
coverage, and assurance-control review dates:

```bash
python src/code-security/scripts/validate_data.py
```

Run the automated tests:

```bash
python -m unittest discover -s tests -v
```

GitHub Actions runs both commands on every push and pull request. The current
workflow validates the knowledge base and Python search behavior; it does not
yet perform end-to-end tests of every AI integration or act as a project-wide
SAST scanner.

## Repository Structure

```text
code-security-skill/
|-- README.md
|-- package.json
|-- bin/
|   `-- codesecurity.js              # npm CLI
|-- scripts/
|   `-- install_skill.py             # Multi-platform installer/uninstaller
|-- src/
|   `-- code-security/
|       |-- data/                    # Versioned security knowledge base
|       |-- scripts/
|       |   |-- search.py            # BM25 and keyword search
|       |   `-- validate_data.py     # Schema and coverage validation
|       |-- templates/               # Always-on AI instruction templates
|       `-- mcp_server.py            # Local stdio MCP server
|-- tests/
|   `-- test_search.py
`-- .github/workflows/test.yml
```

## Troubleshooting

### The MCP server does not appear

1. Confirm `python -m pip show mcp` succeeds.
2. Confirm `~/.code-security-skill/mcp_server.py` exists.
3. Inspect the platform-specific MCP configuration listed above.
4. Restart or reload the AI coding tool.
5. Re-run installation with `--force` if the configuration is stale.

### Python is not found

Try `python3` on Unix-like systems or `py -3` on Windows. Ensure the selected
interpreter is available on `PATH`.

### The AI did not call `search_security`

MCP tool invocation is controlled by the AI client. Ask it explicitly to use
`search_security`, confirm the static rules file is loaded, and verify that the
client has enabled the `code-security` MCP server.

### Installing into this repository fails

This is intentional. Run the installer from a separate target project. The
repository keeps only `src/code-security` as its source of truth.

## Security Model and Limitations

This project helps AI assistants retrieve and apply secure-development
guidance. It cannot guarantee vulnerability-free code and does not:

- automatically scan every source file;
- execute SAST, DAST, SCA, secret scanning, fuzzing, or penetration tests;
- verify runtime configuration or infrastructure;
- replace project-specific threat modeling or expert review.

For production systems, enforce security independently in CI/CD and during
review. Treat AI-generated security decisions as recommendations that require
verification.

## Contributing

Contributions are welcome. Useful areas include:

- vulnerability profiles and precise CWE mappings;
- additional language and framework rules;
- new feature-specific security checklists;
- MCP and installer integration tests;
- references, test cases, and knowledge-base validation.

Before submitting changes:

```bash
python src/code-security/scripts/validate_data.py
python -m unittest discover -s tests -v
```

## References

- [OWASP Top 10 2025](https://owasp.org/Top10/2025/en/)
- [OWASP API Security Top 10 2023](https://owasp.org/API-Security/editions/2023/en/0x11-t10/)
- [OWASP Top 10 for LLM Applications](https://genai.owasp.org/llm-top-10/)
- [OWASP ASVS 5.0.0](https://github.com/OWASP/ASVS/tree/v5.0.0)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [MITRE CWE Top 25 2025](https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

## License

MIT, as declared in [`package.json`](package.json).
