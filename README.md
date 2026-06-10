# 🛡️ Code Security Skill

[![License: MIT](https://img.shields.io/badge/license-MIT-green?style=for-the-badge)](LICENSE)
[![OWASP Top 10](https://img.shields.io/badge/OWASP_Top_10-2025-red?style=for-the-badge)](https://owasp.org/Top10/2025/en/)
[![50 Vulnerability Profiles](https://img.shields.io/badge/vulnerability_profiles-50-orange?style=for-the-badge)]()
[![Python 3.x](https://img.shields.io/badge/python-3.x-yellow?style=for-the-badge&logo=python&logoColor=white)]()

> An AI Skill that automatically applies military-grade security standards when engineers write code.  
> No more SQL injection, hardcoded secrets, broken authentication, or XSS — by default, not by request.

---

## The Problem

Engineers write insecure code — not because they're careless, but because security patterns are easy to forget, verbose to implement, and rarely enforced by default.

```python
# An engineer writes this innocently:
user = db.execute(f"SELECT * FROM users WHERE id={user_id}")

# They didn't know this is a textbook SQL injection vulnerability.
```

**Code Security Skill fixes this at the source — before the code is written.**

---

## How It Works

```
┌───────────────────────────────────────────────────────────┐
│  ENGINEER SAYS: "Build me a login system"                 │
└───────────────────────────────────────────────────────────┘
                           │
                           ▼
┌───────────────────────────────────────────────────────────┐
│  SKILL ACTIVATES                                          │
│  → Identifies feature type (auth)                         │
│  → Loads vulnerability profile (A01, A02, A07)            │
│  → Loads 10-item auth security checklist                  │
│  → Selects secure libraries (bcrypt, secrets)             │
└───────────────────────────────────────────────────────────┘
                           │
                           ▼
┌───────────────────────────────────────────────────────────┐
│  AI WRITES SECURE CODE BY DEFAULT                         │
│  ✅ bcrypt password hashing (rounds=12)                   │
│  ✅ Rate limiting (5 attempts/minute)                     │
│  ✅ Cryptographically random session tokens               │
│  ✅ HttpOnly + Secure + SameSite cookies                  │
│  ✅ Generic error messages (no username enumeration)      │
│  ✅ Security notes block appended to output               │
└───────────────────────────────────────────────────────────┘
```

---

## Features

- **50 vulnerability profiles** — includes complete category coverage for OWASP API Security Top 10 2023 and OWASP LLM Top 10 2025
- **26 Feature-specific security checklists** — Auth, API, NoSQL, LLM, CI/CD, privacy, WebSocket, serverless, mobile, native memory safety, incident response, and more
- **51 Language, framework & engineering rules** — Python, JS/TS, PHP, Java, Go, Ruby, C#, C/C++, Rust, Terraform, and shared practices
- **12 Cryptography guides** — bcrypt, argon2, AES-256-GCM, HMAC, JWT, mTLS, **secrets management, KMS, secure token storage**
- **OWASP ASVS 5.0.0 index** — searchable coverage of all 17 chapters and the official 345-requirement total
- **MITRE CWE Top 25 2025 index** — complete ranked root-cause coverage, including native memory-safety weaknesses
- **Extended CWE mappings** — precise searchable mappings for SSTI (`CWE-1336`) and NoSQL Injection (`CWE-943`)
- **15 governed assurance controls** — threat modeling, SAST, DAST, secrets, SBOM, provenance, fuzzing, IaC, incident response, and privacy lifecycle
- **Validated BM25 + keyword hybrid search engine** — supports common Traditional Chinese queries, explicit no-result responses, and legacy Windows terminals
- **Auto-activation** — triggers on 50+ keywords including modern ones (llm, prompt, agent, supply chain, kubernetes, graphql, oauth, …)

### What's New in v2.0

- 🆕 **OWASP 2025 alignment** — Software Supply Chain Failures (A03) and Mishandling of Exceptional Conditions (A10), SSRF merged into Broken Access Control
- 🤖 **LLM/AI security** — prompt injection (direct + indirect), insecure output handling, excessive agency, sensitive disclosure
- 🔌 **API security** — BOLA, BFLA, unrestricted resource consumption
- 📦 **Supply chain security** — dependency pinning, SCA scanning, typosquatting defense
- ☁️ **Cloud & container** — IAM least-privilege, secret managers, image scanning

---

## Installation

### For Claude Code

```bash
# Clone the source repository
git clone https://github.com/your-org/code-security-skill.git /tmp/code-security-skill

# Install into another project
python3 /tmp/code-security-skill/scripts/install_skill.py /path/to/your-project
```

Use `--force` to replace a previously installed copy:

```bash
python3 scripts/install_skill.py /path/to/your-project --force
```

`src/code-security` is the only source of truth in this repository. Generated
`.claude/skills/code-security` installations are intentionally not committed.

### Prerequisites

```bash
python3 --version  # Python 3.x required

# Optional (for MIME type validation examples)
pip install python-magic
```

---

## Usage

### Auto-activate (Recommended)

The skill activates automatically when you ask Claude Code for any feature involving security-sensitive code:

```
Build a login system with JWT
Create an API endpoint for user profiles
Add file upload to the dashboard
Write a password reset flow
Set up payment processing with Stripe
```

### Manual Search Commands

```bash
# Full security report for a feature
python3 .claude/skills/code-security/scripts/search.py "login authentication" --lang python

# Get security checklist only
python3 .claude/skills/code-security/scripts/search.py "file upload" --mode checklist

# Look up a vulnerability
python3 .claude/skills/code-security/scripts/search.py "sql injection" --mode vuln

# Get crypto recommendations
python3 .claude/skills/code-security/scripts/search.py "password hashing" --mode crypto

# Language-specific rules
python3 .claude/skills/code-security/scripts/search.py "database query" --mode rules --lang javascript

# Verification standards and security assurance
python3 .claude/skills/code-security/scripts/search.py "authentication" --mode asvs
python3 .claude/skills/code-security/scripts/search.py "memory buffer" --mode cwe
python3 .claude/skills/code-security/scripts/search.py "sast sbom secret scanning" --mode control

# Validate every source knowledge-base CSV before release
python3 src/code-security/scripts/validate_data.py

# Run the automated test suite
python3 -m unittest discover -s tests -v
```

---

## Example Output

```
════════════════════════════════════════════════════════════════════════════════════════
  🛡️  CODE SECURITY SKILL — SECURITY ANALYSIS REPORT
  Query: "login authentication"  |  Language: python
════════════════════════════════════════════════════════════════════════════════════════

────────────────────────────────────────────────────────────────────────────────────────
  📋  FEATURE SECURITY CHECKLIST  (apply before writing any code)
────────────────────────────────────────────────────────────────────────────────────────
  📋 Authentication System — Security Checklist
     Severity if skipped: 🔴 CRITICAL

     ✅ [AUTH-1] Hash passwords with bcrypt/argon2 (never MD5/SHA1/plain)
     ✅ [AUTH-2] Implement account lockout after N failed attempts
     ✅ [AUTH-3] Enforce password complexity (min 8 chars, mixed case, numbers, symbols)
     ✅ [AUTH-4] Use secure session tokens (cryptographically random, 128-bit+)
     ✅ [AUTH-5] Set session timeout and re-auth for sensitive actions
     ✅ [AUTH-6] Implement MFA/2FA for sensitive accounts
     ✅ [AUTH-7] Log all auth events (success + failure) without logging passwords
     ✅ [AUTH-8] Use HTTPS only (reject HTTP for auth endpoints)
     ✅ [AUTH-9] Prevent username enumeration (same response for unknown vs wrong)
     ✅ [AUTH-10] Implement CSRF protection on all auth forms

     📦 PY libs: bcrypt/argon2-cffi
     📦 JS libs: bcrypt

────────────────────────────────────────────────────────────────────────────────────────
  ⚠️   VULNERABILITIES TO GUARD AGAINST
────────────────────────────────────────────────────────────────────────────────────────
  🔴 [V005] Broken Authentication — CRITICAL
     Category: Auth Failures | OWASP: A07:2025
     Risk: Weak or missing authentication mechanisms
     Fix: Use bcrypt/argon2 for passwords; implement MFA; secure session management
  ...
```

---

## Vulnerability Coverage

| ID | Vulnerability | Severity | OWASP |
|----|--------------|----------|-------|
| V001 | SQL Injection | 🔴 CRITICAL | A05:2025 |
| V002 | Command Injection | 🔴 CRITICAL | A05:2025 |
| V003 | XSS (Cross-Site Scripting) | 🟠 HIGH | A05:2025 |
| V004 | Hardcoded Secrets | 🔴 CRITICAL | A04:2025 |
| V005 | Broken Authentication | 🔴 CRITICAL | A07:2025 |
| V006 | IDOR / Broken Access Control | 🟠 HIGH | A01:2025 |
| V007 | Path Traversal | 🟠 HIGH | A01:2025 |
| V008 | Insecure Deserialization | 🟠 HIGH | A08:2025 |
| V009 | Missing Rate Limiting | 🟡 MEDIUM | A06:2025 |
| V010 | Sensitive Data in Logs | 🟠 HIGH | A09:2025 |
| V011 | JWT Vulnerabilities | 🟠 HIGH | A07:2025 |
| V012 | CSRF | 🟠 HIGH | A01:2025 |
| V013 | Mass Assignment | 🟠 HIGH | A01:2025 |
| V014 | Weak Cryptography | 🟠 HIGH | A04:2025 |
| V015 | Open Redirect | 🟡 MEDIUM | A01:2025 |
| V016 | Server-Side Request Forgery (SSRF) | 🔴 CRITICAL | A01:2025 |
| V017 | Prototype Pollution | 🟠 HIGH | A08:2025 |
| V018 | ReDoS | 🟡 MEDIUM | A06:2025 |
| V019 | Insecure File Upload | 🟠 HIGH | A05:2025 |
| V020 | Missing Security Headers | 🟡 MEDIUM | A02:2025 |
| V021 | Software Supply Chain Failure | 🔴 CRITICAL | A03:2025 🆕 |
| V022 | Mishandling of Exceptional Conditions | 🟠 HIGH | A10:2025 🆕 |
| V023 | Security Misconfiguration | 🟠 HIGH | A02:2025 |
| V024 | Prompt Injection (LLM) | 🔴 CRITICAL | LLM01:2025 🤖 |
| V025 | Insecure LLM Output Handling | 🟠 HIGH | LLM05:2025 🤖 |
| V026 | Excessive Agency (LLM) | 🟠 HIGH | LLM06:2025 🤖 |
| V027 | Sensitive Information Disclosure (LLM) | 🟠 HIGH | LLM02:2025 🤖 |
| V028 | Broken Object Level Authorization (BOLA) | 🔴 CRITICAL | API1:2023 🔌 |
| V029 | Broken Function Level Authorization (BFLA) | 🟠 HIGH | API5:2023 🔌 |
| V030 | Unrestricted Resource Consumption (API) | 🟡 MEDIUM | API4:2023 🔌 |
| V031 | XML External Entity (XXE) | 🟠 HIGH | A05:2025 |
| V032 | Insufficient Logging & Monitoring | 🟡 MEDIUM | A09:2025 |
| V033 | Race Condition / TOCTOU | 🟠 HIGH | CWE-362 |
| V034 | Insecure Cookie Configuration | 🟡 MEDIUM | A02:2025 |
| V035 | Container & Cloud Misconfiguration | 🟠 HIGH | A02:2025 ☁️ |
| V036–V040, V047–V048 | Remaining OWASP API Security Top 10 2023 categories | 🟡–🔴 | API2/3/6/7/8/9/10:2023 |
| V041–V046 | Remaining OWASP LLM Top 10 2025 categories | 🟡–🟠 | LLM03/04/07/08/09/10:2025 |

---

## File Structure

```
code-security-skill/
├── README.md
├── CLAUDE.md
├── scripts/
│   └── install_skill.py               ← Install source into another project
├── src/
│   └── code-security/
│       ├── data/
│       │   ├── vulnerabilities.csv    ← 50 vulnerability profiles
│       │   ├── rules.csv              ← 51 secure engineering rules
│       │   ├── checklists.csv         ← 26 feature checklists
│       │   ├── crypto.csv             ← 12 cryptography guides
│       │   ├── asvs.csv               ← ASVS 5.0.0 chapter index
│       │   ├── cwe_top25.csv          ← MITRE CWE Top 25 2025
│       │   ├── cwe_extended.csv       ← precise additional CWE mappings
│       │   └── assurance.csv          ← governed assurance controls
│       ├── scripts/
│       │   ├── search.py              ← BM25 search engine
│       │   └── validate_data.py       ← schema and coverage validation
│       └── templates/
│           ├── skill-content.md       ← Core skill instructions
│           └── claude.json            ← Platform config
```

---

## Contributing

PRs welcome! Areas to contribute:
- More vulnerability patterns
- Additional language rules (Rust, Swift, Kotlin, Elixir)
- Framework-specific rules (Django, Rails, Laravel, Spring Boot, NestJS)
- More feature checklists (OAuth2, WebSockets, GraphQL, gRPC)

This skill is a secure-development aid, not a replacement for threat modeling,
security testing, dependency scanning, secret scanning, or expert review.

---

## References

- [OWASP Top 10 2025](https://owasp.org/Top10/2025/en/)
- [OWASP ASVS 5.0.0](https://github.com/OWASP/ASVS/tree/v5.0.0)
- [MITRE CWE Top 25 2025](https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

---

## License

MIT License — Use freely, contribute back.

---

*Inspired by [UI/UX Pro Max Skill](https://github.com/nextlevelbuilder/ui-ux-pro-max-skill) — bringing the same "intelligence by default" philosophy to application security.*
