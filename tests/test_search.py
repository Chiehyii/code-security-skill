import importlib.util
import io
import json
import os
import re
import subprocess
import sys
import tempfile
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
        self.assertTrue(all(
            row["reference"].endswith(":2023")
            for row in rules if row["reference"].startswith("OWASP API")
        ))
        self.assertTrue(all(
            row["reference"].endswith(":2025")
            for row in rules if row["reference"].startswith("OWASP LLM")
        ))

    def test_llm_top_10_2025_is_covered(self):
        rows = security_search.load_csv("vulnerabilities.csv")
        references = {row["owasp_ref"] for row in rows}
        self.assertTrue({f"LLM{number:02}:2025" for number in range(1, 11)} <= references)

    def test_asvs_and_cwe_indexes_are_complete(self):
        asvs = security_search.load_csv("asvs.csv")
        cwe = security_search.load_csv("cwe_top25.csv")
        self.assertEqual({f"V{number}" for number in range(1, 18)}, {row["id"] for row in asvs})
        self.assertEqual(345, sum(int(row["requirements"]) for row in asvs))
        self.assertEqual(set(range(1, 26)), {int(row["rank"]) for row in cwe})

    def test_installer_creates_matching_skill_from_single_source(self):
        installer_path = os.path.join(ROOT, "scripts", "install_skill.py")
        spec = importlib.util.spec_from_file_location("install_skill", installer_path)
        install_skill = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(install_skill)

        with tempfile.TemporaryDirectory() as target:
            deployed = install_skill.install(target)
            source = os.path.join(ROOT, "src", "code-security")
            for relative_file in [
                os.path.join("data", filename)
                for filename in security_search.EXPECTED_FIELDS
            ] + [
                os.path.join("scripts", "search.py"),
                os.path.join("scripts", "validate_data.py"),
                os.path.join("templates", "skill-content.md"),
                os.path.join("templates", "claude.json"),
            ]:
                with open(os.path.join(source, relative_file), "rb") as source_file:
                    source_bytes = source_file.read()
                with open(os.path.join(deployed, relative_file), "rb") as deployed_file:
                    deployed_bytes = deployed_file.read()
                self.assertEqual(source_bytes, deployed_bytes, relative_file)

    def test_installer_refuses_to_duplicate_inside_source_repository(self):
        installer_path = os.path.join(ROOT, "scripts", "install_skill.py")
        spec = importlib.util.spec_from_file_location("install_skill", installer_path)
        install_skill = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(install_skill)
        with self.assertRaises(ValueError):
            install_skill.install(ROOT)

    def test_source_repository_does_not_store_generated_skill_copy(self):
        generated_copy = os.path.join(ROOT, ".claude", "skills", "code-security")
        self.assertFalse(os.path.exists(generated_copy))

    def test_skill_manifest_is_valid_and_exposes_new_modes(self):
        manifest_path = os.path.join(
            ROOT, "src", "code-security", "templates", "claude.json"
        )
        with open(manifest_path, encoding="utf-8") as manifest_file:
            manifest = json.load(manifest_file)
        self.assertEqual("3.0.0", manifest["version"])
        self.assertTrue({"asvs", "cwe", "control"} <= set(manifest["commands"]))


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

    def test_memory_query_finds_native_cwe_and_checklist(self):
        cwe = security_search.search_rows(
            "記憶體安全 buffer", security_search.load_csv("cwe_top25.csv"), top_n=5
        )
        checklists = security_search.search_checklists(
            "記憶體安全 native", security_search.load_csv("checklists.csv"), top_n=5
        )
        self.assertTrue(any(row["category"] == "Memory Safety" for row in cwe))
        self.assertTrue(any(row["feature"] == "Native / Memory-Safe Code" for row in checklists))

    def test_assurance_query_finds_pipeline_controls(self):
        controls = security_search.search_rows(
            "sast sbom secret scanning", security_search.load_csv("assurance.csv"), top_n=8
        )
        ids = {row["id"] for row in controls}
        self.assertTrue({"A004", "A005", "A006"} <= ids)

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

    def test_bm25_prefers_ssti_for_template_injection_query(self):
        rows = security_search.load_csv("vulnerabilities.csv")
        results = security_search.search_rows("template injection jinja2 render", rows, top_n=3)
        self.assertEqual(results[0]["id"], "V049")

    def test_bm25_prefers_nosql_injection_for_mongodb_query(self):
        rows = security_search.load_csv("vulnerabilities.csv")
        results = security_search.search_rows("mongodb nosql operator injection", rows, top_n=3)
        self.assertEqual(results[0]["id"], "V050")

    def test_chinese_template_query_finds_ssti(self):
        rows = security_search.load_csv("vulnerabilities.csv")
        results = security_search.search_rows("樣板注入 jinja2", rows, top_n=3)
        ids = {row["id"] for row in results}
        self.assertIn("V049", ids)

    def test_chinese_nosql_query_finds_nosql_injection(self):
        rows = security_search.load_csv("vulnerabilities.csv")
        results = security_search.search_rows("非關聯式資料庫 mongodb", rows, top_n=3)
        ids = {row["id"] for row in results}
        self.assertIn("V050", ids)


if __name__ == "__main__":
    unittest.main()
