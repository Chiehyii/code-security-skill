# Code Security Skill — CLAUDE.md

## What This Skill Does

This skill provides **automatic security intelligence** for every code generation request.  
When activated, Claude will apply the highest security standards **by default**, without needing to be asked.

## How to Use the Search Engine

The skill includes a Python-based search engine (BM25 + keyword hybrid) that retrieves:
- Vulnerability profiles (48 profiles, including all OWASP API Top 10 2023 and OWASP LLM Top 10 2025 categories)
- Feature-specific security checklists (25 features including CI/CD, privacy, WebSocket, serverless, mobile, native code, and incident response)
- Language-specific secure engineering rules (48 rules across Python, JavaScript, PHP, Java, Go, Ruby, C#, C/C++, Rust, Terraform, and frameworks)
- Cryptography recommendations (12 guides: bcrypt, argon2, AES-256-GCM, JWT, mTLS, secrets management, KMS, secure token storage)
- OWASP ASVS 5.0.0 chapter index (17 chapters / 345 requirements)
- MITRE CWE Top 25 2025 root-cause index
- Governed security assurance controls with verification evidence and review dates

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

# Verification areas, root causes, and assurance controls
python3 .claude/skills/code-security/scripts/search.py "authentication" --mode asvs
python3 .claude/skills/code-security/scripts/search.py "memory buffer" --mode cwe
python3 .claude/skills/code-security/scripts/search.py "sast sbom" --mode control

# Validate knowledge-base structure
python3 .claude/skills/code-security/scripts/validate_data.py
```

## Skill Source Structure

```
.claude/skills/code-security/
├── scripts/
│   └── search.py          ← BM25 + keyword search engine
├── data/
│   ├── vulnerabilities.csv ← 48 vulnerability profiles
│   ├── rules.csv           ← 48 secure engineering rules
│   ├── checklists.csv      ← 25 feature-specific security checklists
│   ├── crypto.csv          ← 12 cryptography best practice guides
│   ├── asvs.csv            ← ASVS 5.0.0 chapter index
│   ├── cwe_top25.csv       ← MITRE CWE Top 25 2025
│   └── assurance.csv       ← governed assurance controls
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
| Web A02:2025 | Security Misconfiguration / Cookies / Security Headers |
| Web A03:2025 | **Software Supply Chain Failures (NEW)** |
| Web A04:2025 | Cryptographic Failures / Hardcoded Secrets |
| Web A05:2025 | Injection / XSS / XXE / Unsafe File Upload |
| Web A06:2025 | Insecure Design / Missing Abuse Controls / ReDoS |
| Web A07:2025 | Authentication Failures / JWT |
| Web A08:2025 | Software or Data Integrity Failures / Deserialization |
| Web A09:2025 | Security Logging & Alerting Failures |
| Web A10:2025 | **Mishandling of Exceptional Conditions (NEW)** |
| API1–10:2023 | Complete OWASP API Security Top 10 category coverage |
| LLM01–10:2025 | Complete OWASP LLM Top 10 category coverage |
| CWE-362 | Race Condition / TOCTOU |

## Version

v3.0.0 — ASVS 5.0.0, CWE Top 25 2025, assurance controls, broader platform coverage
