#!/usr/bin/env python3
"""Validate every Code Security Skill CSV file."""

import re

import search


REQUIRED_REFERENCES = {
    "OWASP Web Top 10 2025": {f"A{number:02}:2025" for number in range(1, 11)},
    "OWASP API Security Top 10 2023": {f"API{number}:2023" for number in range(1, 11)},
    "OWASP LLM Top 10 2025": {f"LLM{number:02}:2025" for number in range(1, 11)},
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

    print(f"OK total: {total} validated rows")


if __name__ == "__main__":
    main()
