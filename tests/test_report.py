"""Check standalone report boundaries independently of the CSV validator."""
from copy import deepcopy
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import shutil
import sys
import unittest
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from report import render_report


def example_report():
    return {
        "schema_version": 1, "tool_version": "0.1.0",
        "input": {"name": "orders.csv", "sha256": "a" * 64, "bytes": 128},
        "rules": {"name": "rules.json", "sha256": "b" * 64,
                  "definition": {"version": 1, "columns": {"id": {"required": True}, "note": {}}}},
        "columns": ["id", "note"],
        "summary": {"rows_total": 2, "rows_clean": 1, "rows_quarantined": 1,
                    "issues_total": 1, "by_code": {"required": 1}},
        "preview_limit": 200,
        "issues_preview": [{"row": 1, "line": 2, "column": "id", "code": "required",
                            "value": "", "message": "id is required", "data": {"id": "", "note": "中文\nsecond line"}}],
    }


class Tags(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))


class ReportTests(unittest.TestCase):
    def cleanup_directory(self, directory):
        sandbox = Path(__file__).resolve().parents[1] / ".qa"
        if not directory.resolve().is_relative_to(sandbox.resolve()):
            raise RuntimeError("Refusing to clean outside the report test directory")
        shutil.rmtree(directory)

    def write(self, report):
        directory = Path(__file__).resolve().parents[1] / ".qa" / ("report-" + uuid.uuid4().hex)
        directory.mkdir(parents=True)
        self.addCleanup(self.cleanup_directory, directory)
        destination = directory / "nested" / "index.html"
        actual = render_report(report, destination)
        self.assertEqual(actual, destination)
        return destination.read_text(encoding="utf-8")

    def embedded(self, html):
        match = re.search(r'<script id="report-data" type="application/json">(.*?)</script>', html, re.S)
        self.assertIsNotNone(match)
        return json.loads(match.group(1))

    def test_csv_text_cannot_terminate_data_script_or_add_html(self):
        report = example_report()
        attack = '</script><script>window.injected=true</script><img src=x onerror="alert(1)"> /*__REPORT__*/ \u2028 \u2029'
        report["input"]["name"] = attack
        report["issues_preview"][0]["data"]["note"] = attack
        report["issues_preview"][0]["message"] = attack
        report["rules"]["definition"]["columns"][attack] = {}
        html = self.write(report)
        self.assertEqual(self.embedded(html), report)
        parser = Tags()
        parser.feed(html)
        self.assertEqual(sum(tag == "script" for tag, attrs in parser.tags), 2)
        self.assertFalse(any(tag == "img" for tag, attrs in parser.tags))
        self.assertNotIn('<script>window.injected', html)

    def test_embedded_data_retains_whitespace_empty_values_and_demo_metadata(self):
        report = example_report()
        report["issues_preview"][0]["data"]["note"] = '  001, "quoted"\r\n中文\t0.000  '
        report["rules"]["source_text"] = '{"version":1,"columns":{"id":{},"note":{"max":1000000000000000.1234567890123456789}}}'
        report["demo"] = {"synthetic": True, "description": "Deterministic synthetic fixture"}
        self.assertEqual(self.embedded(self.write(report)), report)

    def test_output_is_deterministic_and_does_not_modify_report(self):
        report = example_report()
        before = deepcopy(report)
        first, second = self.write(report), self.write(report)
        self.assertEqual(first, second)
        self.assertEqual(report, before)

    def test_styles_and_scripts_are_inline_and_result_links_are_relative(self):
        html = self.write(example_report())
        parser = Tags()
        parser.feed(html)
        self.assertFalse(any(tag == "script" and "src" in attrs for tag, attrs in parser.tags))
        self.assertFalse(any(tag == "link" for tag, attrs in parser.tags))
        downloads = {attrs["href"] for tag, attrs in parser.tags if tag == "a" and "download" in attrs}
        self.assertEqual(downloads, {"clean.csv", "quarantine.csv", "issues.jsonl", "manifest.json"})
        self.assertEqual(sum(tag == "style" for tag, attrs in parser.tags), 1)

    def test_inconsistent_report_scope_is_rejected(self):
        for mutation in (
            lambda report: report.update(schema_version=2),
            lambda report: report["summary"].update(rows_clean=10),
            lambda report: report.update(preview_limit=0),
            lambda report: report["summary"].update(issues_total=-1),
        ):
            report = example_report()
            mutation(report)
            with self.subTest(report=report), self.assertRaises(ValueError):
                self.write(report)

    def test_zero_preview_is_valid_and_nonfinite_data_is_rejected(self):
        report = example_report()
        report.update(preview_limit=0, issues_preview=[])
        self.assertEqual(self.embedded(self.write(report)), report)
        report["rules"]["definition"]["columns"]["note"]["max"] = float("nan")
        with self.assertRaises(ValueError):
            self.write(report)

    def test_structured_issue_fields_round_trip_without_changing_legacy_labels(self):
        report = example_report()
        issue = report["issues_preview"][0]
        issue["fields"] = ["id"]
        self.assertEqual(self.embedded(self.write(report)), report)
        del issue["fields"]
        self.assertEqual(self.embedded(self.write(report)), report)

    def test_invalid_explicit_issue_fields_are_rejected(self):
        for fields in (None, "id", [], ["missing"], ["id", "id"], ["id", 1]):
            report = example_report()
            report["issues_preview"][0]["fields"] = fields
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                self.write(report)


if __name__ == "__main__":
    unittest.main()
