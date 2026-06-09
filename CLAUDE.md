# Code Security Skill — CLAUDE.md

## What This Skill Does

This skill provides **automatic security intelligence** for every code generation request.  
When activated, Claude will apply the highest security standards **by default**, without needing to be asked.

## How to Use the Search Engine

The skill includes a Python-based search engine (BM25 + keyword hybrid) that retrieves:
- Vulnerability profiles (35 vulnerabilities — OWASP Web Top 10 2025, OWASP API Top 10, OWASP LLM Top 10 2025)
- Feature-specific security checklists (17 features: auth, DB, file upload, API, payment, admin, LLM/AI, OAuth2, GraphQL, webhooks, microservices, supply chain, cloud)
- Language-specific secure coding rules (38 rules across Python, JavaScript, PHP, Java, Go, Ruby, C# + frameworks: Django, Flask, Express, Rails, Laravel, Spring)
- Cryptography recommendations (12 guides: bcrypt, argon2, AES-256-GCM, JWT, mTLS, secrets management, KMS, secure token storage)

```bash
# Full security report for any feature
python3 .claude/skills/code-security/scripts/search.py "login authentication" --lang python

# Get checklist for file upload
python3 .claude/skills/code-security/scripts/search.py "file upload" --mode checklist

# Look up a specific vulnerability
python3 .claude/skills/code-security/scripts/search.py "sql injection" --mode vuln

# Get crypto guidance
python3 .claude/skills/code-security/scripts/search.py "password hashing encryption" --mode crypto

# Language-specific rules
python3 .claude/skills/code-security/scripts/search.py "database query" --mode rules --lang javascript
```

## Skill Source Structure

```
.claude/skills/code-security/
├── scripts/
│   └── search.py          ← BM25 + keyword search engine
├── data/
│   ├── vulnerabilities.csv ← 20 OWASP-mapped vulnerabilities
│   ├── rules.csv           ← 20 language-specific secure coding rules
│   ├── checklists.csv      ← 10 feature-specific security checklists
│   └── crypto.csv          ← 8 cryptography best practice guides
└── templates/
    └── skill-content.md    ← Core skill instructions for Claude

```

## Prerequisites

Python 3.x is required for the search script.

```bash
python3 --version

# Install optional dependency for better MIME detection
pip install python-magic  # or pip3 install python-magic
```

## Supported Languages

Python · JavaScript / TypeScript · Node.js · PHP · Java · Go · Ruby · C# / .NET

## Covered Vulnerabilities (OWASP 2025 standards)

Aligned with the **OWASP Top 10 2025** (released Nov 2025), **OWASP API Security Top 10**, and **OWASP Top 10 for LLM Applications 2025**.

| Standard | Coverage |
|----------|----------|
| Web A01:2025 | Broken Access Control / IDOR / SSRF (merged in 2025) |
| Web A02:2025 | Security Misconfiguration / Hardcoded Secrets / Weak Crypto / Cookies |
| Web A03:2025 | **Software Supply Chain Failures (NEW)** + Injection |
| Web A05/A07/A08 | XXE / Auth Failures / Deserialization |
| Web A09:2025 | Insufficient Logging & Monitoring |
| Web A10:2025 | **Mishandling of Exceptional Conditions (NEW)** |
| API1–5 | BOLA / BFLA / Unrestricted Resource Consumption |
| LLM01:2025 | **Prompt Injection (direct + indirect)** |
| LLM02:2025 | Sensitive Information Disclosure |
| LLM05:2025 | Insecure Output Handling |
| LLM06:2025 | Excessive Agency |
| CWE-362 | Race Condition / TOCTOU |

## Version

v2.0.0 — Code Security Skill (OWASP 2025 aligned + LLM/AI + API + Supply Chain coverage)
