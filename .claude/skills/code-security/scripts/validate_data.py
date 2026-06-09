#!/usr/bin/env python3
"""Validate every Code Security Skill CSV file."""

import search


def main():
    total = 0
    for filename in search.EXPECTED_FIELDS:
        rows = search.load_csv(filename)
        total += len(rows)
        print(f"OK {filename}: {len(rows)} rows")
    print(f"OK total: {total} validated rows")


if __name__ == "__main__":
    main()
