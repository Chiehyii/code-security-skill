#!/usr/bin/env python3
"""Validate every Code Security Skill CSV file."""

import re
from datetime import date, timedelta

import search


REQUIRED_REFERENCES = {
    "OWASP Web Top 10 2025": {f"A{number:02}:2025" for number in range(1, 11)},
    "OWASP API Security Top 10 2023": {f"API{number}:2023" for number in range(1, 11)},
    "OWASP LLM Top 10 2025": {f"LLM{number:02}:2025" for number in range(1, 11)},
}

CWE_TOP_25_2025 = {
    "CWE-79", "CWE-89", "CWE-352", "CWE-862", "CWE-787", "CWE-22",
    "CWE-416", "CWE-125", "CWE-78", "CWE-94", "CWE-120", "CWE-434",
    "CWE-476", "CWE-121", "CWE-502", "CWE-122", "CWE-863", "CWE-20",
    "CWE-284", "CWE-200", "CWE-306", "CWE-918", "CWE-77", "CWE-639",
    "CWE-770",
}


def main():
    total = 0
    loaded = {}
    for filename in search.EXPECTED_FIELDS:
        rows = search.load_csv(filename)
        loaded[filename] = rows
        total += len(rows)
        print(f"OK {filename}: {len(rows)} rows")

    references = {
        row["owasp_ref"] for row in loaded["vulnerabilities.csv"]
    }
    for standard, required in REQUIRED_REFERENCES.items():
        missing = sorted(required - references)
        if missing:
            raise ValueError(f"{standard}: missing categories: {', '.join(missing)}")
        print(f"OK {standard}: complete category coverage")

    legacy_web_references = sorted(
        reference for reference in references if reference.endswith(":2021")
    )
    if legacy_web_references:
        raise ValueError(
            f"Legacy OWASP Web references found: {', '.join(legacy_web_references)}"
        )

    web_rule_references = [
        row["reference"] for row in loaded["rules.csv"]
        if re.match(r"^OWASP A\d{2}", row["reference"])
    ]
    invalid_web_rules = sorted(
        reference for reference in web_rule_references
        if not reference.endswith(":2025")
    )
    if invalid_web_rules:
        raise ValueError(
            f"Non-2025 OWASP Web rule references found: {', '.join(invalid_web_rules)}"
        )

    invalid_api_llm_rules = sorted(
        row["reference"] for row in loaded["rules.csv"]
        if (
            row["reference"].startswith("OWASP API")
            and not row["reference"].endswith(":2023")
        ) or (
            row["reference"].startswith("OWASP LLM")
            and not row["reference"].endswith(":2025")
        )
    )
    if invalid_api_llm_rules:
        raise ValueError(
            "Unversioned or invalid OWASP API/LLM rule references found: "
            + ", ".join(invalid_api_llm_rules)
        )

    asvs = loaded["asvs.csv"]
    if {row["id"] for row in asvs} != {f"V{number}" for number in range(1, 18)}:
        raise ValueError("OWASP ASVS 5.0.0 chapter index must contain V1 through V17")
    if sum(int(row["requirements"]) for row in asvs) != 345:
        raise ValueError("OWASP ASVS 5.0.0 chapter index must total 345 requirements")
    if any(row["source_version"] != "OWASP ASVS 5.0.0" for row in asvs):
        raise ValueError("ASVS chapter index contains an unexpected source version")
    print("OK OWASP ASVS 5.0.0: 17 chapters and 345 requirements indexed")

    cwe_rows = loaded["cwe_top25.csv"]
    if {row["id"] for row in cwe_rows} != CWE_TOP_25_2025:
        raise ValueError("MITRE CWE Top 25 2025 index is incomplete or contains unexpected IDs")
    if {int(row["rank"]) for row in cwe_rows} != set(range(1, 26)):
        raise ValueError("MITRE CWE Top 25 2025 ranks must be unique from 1 through 25")
    print("OK MITRE CWE Top 25 2025: complete ranked coverage")

    assurance = loaded["assurance.csv"]
    if len(assurance) < 15:
        raise ValueError("Security assurance control set must contain at least 15 controls")
    if any(not re.match(r"^\d{4}-\d{2}-\d{2}$", row["review_date"]) for row in assurance):
        raise ValueError("Assurance review_date values must use YYYY-MM-DD")
    stale_before = date.today() - timedelta(days=366)
    stale_controls = [
        row["id"] for row in assurance
        if date.fromisoformat(row["review_date"]) < stale_before
    ]
    if stale_controls:
        raise ValueError(
            f"Security assurance controls require annual review: {', '.join(stale_controls)}"
        )
    print(f"OK security assurance controls: {len(assurance)} governed controls")

    print(f"OK total: {total} validated rows")


if __name__ == "__main__":
    main()
