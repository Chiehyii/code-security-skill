import importlib.util
import io
import os
import re
import subprocess
import sys
import unittest
from contextlib import redirect_stdout


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "src", "code-security", "scripts", "search.py")

spec = importlib.util.spec_from_file_location("security_search", SCRIPT)
security_search = importlib.util.module_from_spec(spec)
spec.loader.exec_module(security_search)


class DataIntegrityTests(unittest.TestCase):
    def test_all_csv_files_have_expected_columns_and_unique_ids(self):
        for filename, expected_fields in security_search.EXPECTED_FIELDS.items():
            rows = security_search.load_csv(filename)
            self.assertTrue(rows, filename)
            self.assertEqual(len(rows), len({row["id"] for row in rows}), filename)
            for row in rows:
                self.assertEqual(list(row.keys()), expected_fields, filename)
                self.assertTrue(all(value != "" for value in row.values()), row["id"])

    def test_api_top_10_2023_is_covered(self):
        rows = security_search.load_csv("vulnerabilities.csv")
        references = {row["owasp_ref"] for row in rows}
        self.assertTrue({f"API{number}:2023" for number in range(1, 11)} <= references)

    def test_web_top_10_2025_is_covered_without_legacy_references(self):
        vulnerabilities = security_search.load_csv("vulnerabilities.csv")
        rules = security_search.load_csv("rules.csv")
        references = {row["owasp_ref"] for row in vulnerabilities}
        self.assertTrue({f"A{number:02}:2025" for number in range(1, 11)} <= references)
        self.assertFalse(any("2021" in row["owasp_ref"] for row in vulnerabilities))
        self.assertFalse(any("2021" in row["reference"] for row in rules))
        web_rule_references = [
            row["reference"] for row in rules
            if re.match(r"^OWASP A\d{2}", row["reference"])
        ]
        self.assertTrue(all(reference.endswith(":2025") for reference in web_rule_references))

    def test_llm_top_10_2025_is_covered(self):
        rows = security_search.load_csv("vulnerabilities.csv")
        references = {row["owasp_ref"] for row in rows}
        self.assertTrue({f"LLM{number:02}:2025" for number in range(1, 11)} <= references)

    def test_deployed_skill_copy_matches_source(self):
        relative_files = [
            os.path.join("data", filename)
            for filename in security_search.EXPECTED_FIELDS
        ] + [
            os.path.join("scripts", "search.py"),
            os.path.join("scripts", "validate_data.py"),
            os.path.join("templates", "skill-content.md"),
            os.path.join("templates", "claude.json"),
        ]
        source = os.path.join(ROOT, "src", "code-security")
        deployed = os.path.join(ROOT, ".claude", "skills", "code-security")
        for relative_file in relative_files:
            with open(os.path.join(source, relative_file), "rb") as source_file:
                source_bytes = source_file.read()
            with open(os.path.join(deployed, relative_file), "rb") as deployed_file:
                deployed_bytes = deployed_file.read()
            self.assertEqual(source_bytes, deployed_bytes, relative_file)


class SearchTests(unittest.TestCase):
    def test_chinese_query_matches_authentication_and_upload(self):
        rows = security_search.load_csv("checklists.csv")
        matches = security_search.search_checklists("登入驗證與檔案上傳", rows, top_n=5)
        features = {row["feature"] for row in matches}
        self.assertIn("Authentication System", features)
        self.assertIn("File Upload", features)

    def test_unknown_checklist_query_returns_no_results(self):
        rows = security_search.load_csv("checklists.csv")
        self.assertEqual(
            security_search.search_checklists("quantum banana", rows, top_n=3),
            [],
        )

    def test_bm25_prefers_sql_injection(self):
        rows = security_search.load_csv("vulnerabilities.csv")
        results = security_search.search_rows("sql injection", rows, top_n=3)
        self.assertEqual(results[0]["id"], "V001")

    def test_generic_security_word_does_not_dilute_llm_results(self):
        rows = security_search.load_csv("vulnerabilities.csv")
        results = security_search.search_rows("llm security", rows, top_n=10)
        self.assertEqual(10, len(results))
        self.assertTrue(all(row["owasp_ref"].startswith("LLM") for row in results))

    def test_language_filter_keeps_all_language_rules(self):
        rows = security_search.load_csv("rules.csv")
        filtered = [
            row for row in rows
            if row["language"] in ("python", "all")
        ]
        self.assertTrue(any(row["language"] == "all" for row in filtered))
        self.assertFalse(any(row["language"] == "javascript" for row in filtered))

    def test_cli_prints_explicit_no_result_message(self):
        result = subprocess.run(
            [sys.executable, SCRIPT, "quantum banana", "--mode", "checklist"],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        self.assertIn("No relevant checklist guidance found", result.stdout)

    def test_report_runs_without_unicode_terminal_dependency(self):
        output = io.StringIO()
        with redirect_stdout(output):
            security_search.generate_security_report("登入 api")
        self.assertIn("SECURITY ANALYSIS REPORT", output.getvalue())


if __name__ == "__main__":
    unittest.main()
