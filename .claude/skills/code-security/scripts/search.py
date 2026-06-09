#!/usr/bin/env python3
"""
Code Security Skill - Search Engine
BM25 + keyword hybrid search for security vulnerabilities, rules, and checklists.
Usage:
  python3 search.py "login feature" --mode checklist
  python3 search.py "sql injection" --mode vuln
  python3 search.py "password hashing" --mode crypto
  python3 search.py "file upload" --mode all
"""

import csv
import sys
import os
import re
import math
import argparse
from collections import defaultdict

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, '..', 'data')

# ─── CSV Loaders ───────────────────────────────────────────────────────────────

def load_csv(filename):
    path = os.path.join(DATA_DIR, filename)
    with open(path, newline='', encoding='utf-8') as f:
        return list(csv.DictReader(f))

# ─── Simple BM25 Scorer ────────────────────────────────────────────────────────

def tokenize(text):
    return re.findall(r'[a-z0-9]+', text.lower())

def bm25_score(query_tokens, doc_tokens, k1=1.5, b=0.75, avg_dl=20):
    doc_len = len(doc_tokens)
    freq = defaultdict(int)
    for t in doc_tokens:
        freq[t] += 1
    score = 0.0
    for qt in query_tokens:
        f = freq.get(qt, 0)
        if f == 0:
            continue
        idf = math.log((100 + 0.5) / (1 + 1) + 1)
        tf = (f * (k1 + 1)) / (f + k1 * (1 - b + b * doc_len / avg_dl))
        score += idf * tf
    return score

def score_row(query_tokens, row):
    text = ' '.join(str(v) for v in row.values())
    return bm25_score(query_tokens, tokenize(text))

def search_rows(query, rows, top_n=5):
    tokens = tokenize(query)
    scored = [(score_row(tokens, r), r) for r in rows]
    scored.sort(key=lambda x: x[0], reverse=True)
    return [r for s, r in scored if s > 0][:top_n]

# ─── Keyword Trigger Match ─────────────────────────────────────────────────────

def keyword_match(query, trigger_field):
    query_words = set(tokenize(query))
    triggers = set(tokenize(trigger_field))
    return len(query_words & triggers)

# ─── Output Formatters ─────────────────────────────────────────────────────────

SEVERITY_COLORS = {
    'CRITICAL': '🔴',
    'HIGH':     '🟠',
    'MEDIUM':   '🟡',
    'LOW':      '🟢',
}

def fmt_vuln(v):
    icon = SEVERITY_COLORS.get(v.get('severity', ''), '⚪')
    lines = [
        f"  {icon} [{v['id']}] {v['name']} — {v['severity']}",
        f"     Category : {v['category']}",
        f"     OWASP    : {v['owasp_ref']}",
        f"     Risk     : {v['description']}",
        f"     Fix      : {v['fix_pattern']}",
    ]
    return '\n'.join(lines)

def fmt_checklist(row, query=''):
    items = row['checklist'].split('|')
    lines = [
        f"  📋 {row['feature']} — Security Checklist",
        f"     Severity if skipped: {SEVERITY_COLORS.get(row['severity_if_skipped'],'')} {row['severity_if_skipped']}",
        '',
    ]
    for item in items:
        lines.append(f"     {'✅' if True else '☐'} {item.strip()}")
    if row.get('required_libs_js') and row['required_libs_js'] != 'N/A':
        lines.append(f"\n     📦 JS  libs : {row['required_libs_js']}")
    if row.get('required_libs_python') and row['required_libs_python'] != 'N/A':
        lines.append(f"     📦 PY  libs : {row['required_libs_python']}")
    return '\n'.join(lines)

def fmt_crypto(row):
    lines = [
        f"  🔐 [{row['id']}] {row['use_case']}",
        f"     ✅ Use     : {row['recommended']}",
        f"     ❌ Avoid   : {row['avoid']}",
        f"     ℹ️  Notes   : {row['notes']}",
    ]
    return '\n'.join(lines)

def fmt_rule(row):
    lines = [
        f"  📏 [{row['id']}] {row['language'].upper()} — {row['category']}",
        f"     Rule     : {row['rule']}",
        f"     ❌ Bad    : {row['bad_example'][:80]}",
        f"     ✅ Good   : {row['good_example'][:80]}",
    ]
    return '\n'.join(lines)

# ─── Security Report Generator ────────────────────────────────────────────────

def generate_security_report(query, language=None):
    vulns      = load_csv('vulnerabilities.csv')
    rules      = load_csv('rules.csv')
    checklists = load_csv('checklists.csv')
    crypto     = load_csv('crypto.csv')

    # Find matching checklists by keyword trigger
    matched_checklists = sorted(
        checklists,
        key=lambda r: keyword_match(query, r['trigger_keywords']),
        reverse=True
    )[:2]

    # Find relevant vulnerabilities
    matched_vulns = search_rows(query, vulns, top_n=4)

    # Language-specific rules
    if language:
        lang_rules = [r for r in rules if r['language'] in (language, 'all')]
        matched_rules = search_rows(query, lang_rules, top_n=3)
    else:
        matched_rules = search_rows(query, rules, top_n=3)

    # Crypto recommendations
    matched_crypto = search_rows(query, crypto, top_n=2)

    # ─── Print Report ─────────────────────────────────────────────────────────
    width = 88
    print('=' * width)
    print(f"  🛡️  CODE SECURITY SKILL — SECURITY ANALYSIS REPORT")
    print(f"  Query   : \"{query}\"" + (f"  |  Language: {language}" if language else ''))
    print('=' * width)

    if matched_checklists and keyword_match(query, matched_checklists[0]['trigger_keywords']) > 0:
        print(f"\n{'─'*width}")
        print("  📋  FEATURE SECURITY CHECKLIST  (apply before writing any code)")
        print(f"{'─'*width}")
        for row in matched_checklists:
            if keyword_match(query, row['trigger_keywords']) > 0:
                print(fmt_checklist(row, query))
                print()

    if matched_vulns:
        print(f"\n{'─'*width}")
        print("  ⚠️   VULNERABILITIES TO GUARD AGAINST")
        print(f"{'─'*width}")
        for v in matched_vulns:
            print(fmt_vuln(v))
            print()

    if matched_rules:
        print(f"\n{'─'*width}")
        print("  📏  LANGUAGE-SPECIFIC SECURE CODING RULES")
        print(f"{'─'*width}")
        for r in matched_rules:
            print(fmt_rule(r))
            print()

    if matched_crypto:
        print(f"\n{'─'*width}")
        print("  🔐  CRYPTOGRAPHY RECOMMENDATIONS")
        print(f"{'─'*width}")
        for c in matched_crypto:
            print(fmt_crypto(c))
            print()

    print(f"\n{'─'*width}")
    print("  📌  PRE-DELIVERY SECURITY CHECKLIST")
    print(f"{'─'*width}")
    pre_delivery = [
        "No secrets / API keys hardcoded in source code or committed to Git",
        "All user input validated (type, length, format, allowed chars)",
        "All database queries use parameterized statements",
        "Passwords hashed with bcrypt/argon2 (never MD5/SHA1/plain)",
        "Authentication and authorization checked on EVERY endpoint",
        "Error responses use generic messages (no stack traces in prod)",
        "Rate limiting applied to sensitive endpoints",
        "HTTPS enforced; HTTP requests redirected",
        "Security headers configured (CSP, HSTS, X-Frame-Options, X-Content-Type)",
        "Dependencies up to date; no known CVEs in production deps",
    ]
    for item in pre_delivery:
        print(f"     ☐ {item}")

    print('\n' + '=' * width)
    print("  Generated by Code Security Skill — https://github.com/your-org/code-security-skill")
    print('=' * width)

# ─── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description='Code Security Skill Search Engine')
    parser.add_argument('query', help='Feature or topic to search (e.g. "login api file upload")')
    parser.add_argument('--mode', choices=['all', 'vuln', 'checklist', 'crypto', 'rules'],
                        default='all', help='Search mode')
    parser.add_argument('--lang', '--language', dest='language',
                        help='Programming language filter (python, javascript, php, java, go, ruby, csharp)')
    parser.add_argument('-n', '--top', type=int, default=5, help='Number of results')
    args = parser.parse_args()

    if args.mode == 'all':
        generate_security_report(args.query, language=args.language)
    elif args.mode == 'vuln':
        rows = search_rows(args.query, load_csv('vulnerabilities.csv'), args.top)
        for r in rows:
            print(fmt_vuln(r))
            print()
    elif args.mode == 'checklist':
        rows = load_csv('checklists.csv')
        rows = sorted(rows, key=lambda r: keyword_match(args.query, r['trigger_keywords']), reverse=True)
        for r in rows[:3]:
            print(fmt_checklist(r))
            print()
    elif args.mode == 'crypto':
        rows = search_rows(args.query, load_csv('crypto.csv'), args.top)
        for r in rows:
            print(fmt_crypto(r))
            print()
    elif args.mode == 'rules':
        all_rules = load_csv('rules.csv')
        if args.language:
            all_rules = [r for r in all_rules if r['language'] in (args.language, 'all')]
        rows = search_rows(args.query, all_rules, args.top)
        for r in rows:
            print(fmt_rule(r))
            print()

if __name__ == '__main__':
    main()
