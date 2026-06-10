#!/usr/bin/env python3
"""
Code Security Skill - Search Engine

Validated CSV loading plus BM25 and trigger-keyword search.
"""

import argparse
import csv
import math
import os
import re
import sys
from collections import Counter


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.normpath(os.path.join(BASE_DIR, "..", "data"))

EXPECTED_FIELDS = {
    "vulnerabilities.csv": [
        "id", "name", "category", "severity", "owasp_ref", "description",
        "trigger_keywords", "fix_pattern", "languages",
    ],
    "rules.csv": [
        "id", "language", "category", "rule", "bad_example", "good_example",
        "reference",
    ],
    "checklists.csv": [
        "id", "feature", "trigger_keywords", "checklist",
        "required_libs_python", "required_libs_js", "severity_if_skipped",
    ],
    "crypto.csv": [
        "id", "use_case", "recommended", "avoid", "notes", "python_code",
        "javascript_code",
    ],
    "asvs.csv": [
        "id", "name", "requirements", "focus", "trigger_keywords",
        "source_version",
    ],
    "cwe_top25.csv": [
        "id", "rank", "name", "category", "applies_to", "prevention",
        "trigger_keywords", "source_version",
    ],
    "cwe_extended.csv": [
        "id", "name", "category", "applies_to", "prevention",
        "trigger_keywords", "source_version",
    ],
    "assurance.csv": [
        "id", "phase", "control", "verification", "evidence", "automation",
        "trigger_keywords", "reference", "review_date",
    ],
}

# Common Traditional Chinese feature/security terms. English aliases match the
# knowledge-base vocabulary while Unicode tokenization still supports other text.
QUERY_ALIASES = {
    "登入": "login auth authentication",
    "登錄": "login auth authentication",
    "驗證": "auth authentication validation verify",
    "授權": "authorization access control",
    "密碼": "password hashing",
    "上傳": "file upload",
    "檔案": "file path upload",
    "資料庫": "database sql query",
    "注入": "injection",
    "隱私": "privacy pii sensitive data",
    "機密": "secret sensitive data",
    "日誌": "logging monitoring",
    "記錄": "logging monitoring",
    "雲端": "cloud",
    "供應鏈": "supply chain dependency",
    "金流": "payment",
    "付款": "payment",
    "管理員": "admin",
    "工作階段": "session cookie",
    "權杖": "token jwt",
    "人工智慧": "llm ai",
    "提示詞": "prompt llm",
    "威脅模型": "threat model architecture abuse case",
    "原始碼掃描": "sast static analysis",
    "動態掃描": "dast dynamic scan",
    "軟體物料清單": "sbom dependency supply chain",
    "記憶體": "memory buffer pointer native",
    "行動裝置": "mobile android ios",
    "事件應變": "incident response recovery revoke",
    "資料保留": "retention deletion privacy data",
    "漏洞": "vulnerability security",
    "安全": "security",
    "樣板注入": "template ssti render injection jinja2",
    "模板注入": "template ssti render injection jinja2",
    "非關聯式資料庫": "nosql mongodb document collection injection",
    "文件資料庫": "nosql document database mongodb",
    "樣板": "template render",
    "模板": "template render",
}

SEVERITY_LABELS = {
    "CRITICAL": "[CRITICAL]",
    "HIGH": "[HIGH]",
    "MEDIUM": "[MEDIUM]",
    "LOW": "[LOW]",
}

QUERY_STOP_WORDS = {
    "security", "secure", "vulnerability", "vulnerabilities", "feature",
    "system", "application", "code",
}


def configure_output():
    """Avoid UnicodeEncodeError on legacy Windows terminals."""
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")


def load_csv(filename):
    expected = EXPECTED_FIELDS[filename]
    path = os.path.join(DATA_DIR, filename)
    with open(path, newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != expected:
            raise ValueError(
                f"{filename}: invalid header; expected {expected}, got {reader.fieldnames}"
            )

        rows = []
        seen_ids = set()
        for line_number, row in enumerate(reader, start=2):
            if None in row:
                raise ValueError(
                    f"{filename}:{line_number}: too many columns; quote values containing commas"
                )
            if any(value is None for value in row.values()):
                raise ValueError(f"{filename}:{line_number}: missing column value")
            row = {key: value.strip() for key, value in row.items()}
            if not row["id"]:
                raise ValueError(f"{filename}:{line_number}: missing id")
            if row["id"] in seen_ids:
                raise ValueError(f"{filename}:{line_number}: duplicate id {row['id']}")
            seen_ids.add(row["id"])
            rows.append(row)
        return rows


def expand_query(query):
    lowered = query.lower()
    aliases = [value for key, value in QUERY_ALIASES.items() if key in lowered]
    return " ".join([lowered, *aliases])


def tokenize(text):
    # Match Unicode words and split CJK sequences into characters and bigrams.
    raw_tokens = re.findall(r"[^\W_]+", str(text).lower(), flags=re.UNICODE)
    tokens = []
    for token in raw_tokens:
        tokens.append(token)
        if re.search(r"[\u3400-\u9fff]", token):
            chars = list(token)
            tokens.extend(chars)
            tokens.extend("".join(chars[index:index + 2]) for index in range(len(chars) - 1))
    return tokens


def row_text(row):
    return " ".join(str(value) for value in row.values())


def score_rows(query, rows):
    if not rows:
        return []

    query_tokens = [
        token for token in tokenize(expand_query(query))
        if token not in QUERY_STOP_WORDS
    ]
    if not query_tokens:
        return []

    documents = [tokenize(row_text(row)) for row in rows]
    average_length = sum(len(doc) for doc in documents) / len(documents)
    document_frequency = Counter()
    for document in documents:
        document_frequency.update(set(document))

    scored = []
    for row, document in zip(rows, documents):
        frequencies = Counter(document)
        score = 0.0
        for query_token in query_tokens:
            frequency = frequencies.get(query_token, 0)
            if not frequency:
                continue
            idf = math.log(
                1 + (len(documents) - document_frequency[query_token] + 0.5)
                / (document_frequency[query_token] + 0.5)
            )
            length_normalization = 1.5 * (
                1 - 0.75 + 0.75 * len(document) / max(average_length, 1)
            )
            score += idf * (frequency * 2.5) / (frequency + length_normalization)
        if score > 0:
            scored.append((score, row))

    return sorted(scored, key=lambda item: (-item[0], item[1]["id"]))


def search_rows(query, rows, top_n=5):
    return [row for _, row in score_rows(query, rows)[:top_n]]


def keyword_match(query, trigger_field):
    query_words = set(tokenize(expand_query(query)))
    triggers = set(tokenize(trigger_field))
    return len(query_words & triggers)


def search_checklists(query, rows, top_n=3):
    matches = [
        (keyword_match(query, row["trigger_keywords"]), row)
        for row in rows
    ]
    matches = [match for match in matches if match[0] > 0]
    matches.sort(key=lambda item: (-item[0], item[1]["id"]))
    return [row for _, row in matches[:top_n]]


def fmt_vuln(row):
    return "\n".join([
        f"  {SEVERITY_LABELS.get(row['severity'], '[INFO]')} [{row['id']}] {row['name']}",
        f"     Category : {row['category']}",
        f"     Reference: {row['owasp_ref']}",
        f"     Risk     : {row['description']}",
        f"     Fix      : {row['fix_pattern']}",
    ])


def fmt_checklist(row):
    lines = [
        f"  [CHECKLIST] {row['feature']}",
        f"     Severity if skipped: {row['severity_if_skipped']}",
        "",
    ]
    lines.extend(f"     [ ] {item.strip()}" for item in row["checklist"].split("|"))
    if row["required_libs_js"] != "N/A":
        lines.append(f"\n     JS libs : {row['required_libs_js']}")
    if row["required_libs_python"] != "N/A":
        lines.append(f"     PY libs : {row['required_libs_python']}")
    return "\n".join(lines)


def fmt_crypto(row):
    return "\n".join([
        f"  [CRYPTO] [{row['id']}] {row['use_case']}",
        f"     Use   : {row['recommended']}",
        f"     Avoid : {row['avoid']}",
        f"     Notes : {row['notes']}",
    ])


def fmt_rule(row):
    return "\n".join([
        f"  [RULE] [{row['id']}] {row['language'].upper()} - {row['category']}",
        f"     Rule : {row['rule']}",
        f"     Bad  : {row['bad_example'][:100]}",
        f"     Good : {row['good_example'][:100]}",
        f"     Ref  : {row['reference']}",
    ])


def fmt_asvs(row):
    return "\n".join([
        f"  [ASVS] [{row['id']}] {row['name']}",
        f"     Requirements: {row['requirements']}",
        f"     Focus       : {row['focus']}",
        f"     Source      : {row['source_version']}",
    ])


def fmt_cwe(row):
    rank = f"#{row['rank']} " if row.get("rank") else ""
    return "\n".join([
        f"  [CWE] {rank}{row['id']} - {row['name']}",
        f"     Category  : {row['category']} | Applies to: {row['applies_to']}",
        f"     Prevention: {row['prevention']}",
        f"     Source    : {row['source_version']}",
    ])


def load_cwe_rows():
    return load_csv("cwe_top25.csv") + load_csv("cwe_extended.csv")


def fmt_assurance(row):
    return "\n".join([
        f"  [CONTROL] [{row['id']}] {row['phase']} - {row['control']}",
        f"     Verify    : {row['verification']}",
        f"     Evidence  : {row['evidence']}",
        f"     Automation: {row['automation']}",
        f"     Reference : {row['reference']} | Reviewed: {row['review_date']}",
    ])


def print_section(title, rows, formatter):
    if not rows:
        return
    print(f"\n{'-' * 88}\n  {title}\n{'-' * 88}")
    for row in rows:
        print(formatter(row))
        print()


def print_no_results(query, mode):
    print(f'No relevant {mode} guidance found for "{query}".')


def generate_security_report(query, language=None):
    checklists = search_checklists(query, load_csv("checklists.csv"), top_n=2)
    vulnerabilities = search_rows(query, load_csv("vulnerabilities.csv"), top_n=5)
    rules = load_csv("rules.csv")
    if language:
        rules = [row for row in rules if row["language"] in (language.lower(), "all")]
    rules = search_rows(query, rules, top_n=4)
    crypto = search_rows(query, load_csv("crypto.csv"), top_n=3)
    asvs = search_rows(query, load_csv("asvs.csv"), top_n=3)
    cwe = search_rows(query, load_cwe_rows(), top_n=3)
    assurance = search_rows(query, load_csv("assurance.csv"), top_n=3)

    print("=" * 88)
    print("  CODE SECURITY SKILL - SECURITY ANALYSIS REPORT")
    print(f'  Query: "{query}"' + (f" | Language: {language}" if language else ""))
    print("=" * 88)

    print_section("FEATURE SECURITY CHECKLIST", checklists, fmt_checklist)
    print_section("VULNERABILITIES TO GUARD AGAINST", vulnerabilities, fmt_vuln)
    print_section("SECURE CODING RULES", rules, fmt_rule)
    print_section("CRYPTOGRAPHY RECOMMENDATIONS", crypto, fmt_crypto)
    print_section("ASVS VERIFICATION AREAS", asvs, fmt_asvs)
    print_section("CWE ROOT CAUSES", cwe, fmt_cwe)
    print_section("SECURITY ASSURANCE CONTROLS", assurance, fmt_assurance)

    if not any((checklists, vulnerabilities, rules, crypto, asvs, cwe, assurance)):
        print_no_results(query, "security")

    print_section("PRE-DELIVERY SECURITY CHECKLIST", [{
        "feature": "Baseline controls",
        "severity_if_skipped": "HIGH",
        "checklist": "|".join([
            "No secrets or API keys committed to source control",
            "Input is validated and output is contextually encoded",
            "Database queries are parameterized",
            "Authentication and object/function authorization are tested",
            "Sensitive endpoints have abuse controls and rate limits",
            "Production errors do not disclose internal details",
            "Dependencies and build artifacts are scanned and traceable",
            "Security-relevant events are logged without sensitive values",
        ]),
        "required_libs_js": "N/A",
        "required_libs_python": "N/A",
    }], fmt_checklist)


def main():
    configure_output()
    parser = argparse.ArgumentParser(description="Code Security Skill Search Engine")
    parser.add_argument("query", help='Feature or topic to search, e.g. "login api file upload"')
    parser.add_argument(
        "--mode",
        choices=["all", "vuln", "checklist", "crypto", "rules", "asvs", "cwe", "control"],
        default="all", help="Search mode",
    )
    parser.add_argument(
        "--lang", "--language", dest="language",
        help="Language filter, e.g. python, javascript, php, java, go, ruby, csharp",
    )
    parser.add_argument("-n", "--top", type=int, default=5, help="Number of results")
    args = parser.parse_args()

    if args.top < 1:
        parser.error("--top must be at least 1")

    if args.mode == "all":
        generate_security_report(args.query, language=args.language)
        return

    config = {
        "vuln": ("vulnerabilities.csv", fmt_vuln),
        "crypto": ("crypto.csv", fmt_crypto),
        "rules": ("rules.csv", fmt_rule),
        "asvs": ("asvs.csv", fmt_asvs),
        "control": ("assurance.csv", fmt_assurance),
    }
    if args.mode == "checklist":
        rows = search_checklists(args.query, load_csv("checklists.csv"), args.top)
        formatter = fmt_checklist
    elif args.mode == "cwe":
        rows = search_rows(args.query, load_cwe_rows(), args.top)
        formatter = fmt_cwe
    else:
        filename, formatter = config[args.mode]
        rows = load_csv(filename)
        if args.mode == "rules" and args.language:
            rows = [
                row for row in rows
                if row["language"] in (args.language.lower(), "all")
            ]
        rows = search_rows(args.query, rows, args.top)

    if not rows:
        print_no_results(args.query, args.mode)
        return
    for row in rows:
        print(formatter(row))
        print()


if __name__ == "__main__":
    main()
