"""Behavioral coverage for validation, provenance, and atomic publication."""

import contextlib
import csv
import hashlib
import io
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

import rowguard


class CoreTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "data.csv"
        self.rules = self.root / "rules.json"
        self.counter = 0

    def write_rules(self, columns, unique=None):
        rules = {"version": 1, "columns": columns}
        if unique is not None:
            rules["unique"] = unique
        self.rules.write_text(json.dumps(rules, ensure_ascii=False), encoding="utf-8")

    def write_csv(self, header, rows):
        with self.source.open("w", encoding="utf-8", newline="") as stream:
            writer = csv.writer(stream)
            writer.writerow(header)
            writer.writerows(rows)

    def run_audit(self, **kwargs):
        self.counter += 1
        output = self.root / f"result-{self.counter}"
        report = rowguard.audit(self.source, self.rules, output, **kwargs)
        return report, output

    @staticmethod
    def read_csv(path):
        with path.open(encoding="utf-8", newline="") as stream:
            return list(csv.reader(stream))

    @staticmethod
    def read_issues(output):
        return [json.loads(line) for line in (output / "issues.jsonl").read_text(
            encoding="utf-8"
        ).splitlines()]

    def assert_fatal(self, **kwargs):
        output = self.root / "fatal-output"
        before = self.source.read_bytes()
        with self.assertRaises(rowguard.RowGuardError):
            rowguard.audit(self.source, self.rules, output, **kwargs)
        self.assertFalse(output.exists())
        self.assertEqual(self.source.read_bytes(), before)
        self.assertFalse(list(self.root.glob(".*.rowguard-*")))

    def test_required_optional_zero_and_no_coercion(self):
        self.write_rules({
            "id": {"required": True},
            "count": {"type": "integer", "required": True, "min": 0},
            "amount": {"type": "number", "min": 0},
            "day": {"type": "date"},
            "status": {"choices": ["paid"]},
        })
        rows = [
            ["first", "  +00 ", " ", "\t", ""],
            ["second", "0", "0.000", "2024-02-29", "paid"],
            [" ", "", "", "", ""],
        ]
        self.write_csv(["id", "count", "amount", "day", "status"], rows)
        report, output = self.run_audit()
        self.assertEqual(report["summary"], {
            "rows_total": 3, "rows_clean": 2, "rows_quarantined": 1,
            "issues_total": 2, "by_code": {"required": 2},
        })
        self.assertEqual(self.read_csv(output / "clean.csv")[1:], rows[:2])
        self.assertEqual(self.read_csv(output / "quarantine.csv")[1:], rows[2:])

    def test_ascii_integer_grammar(self):
        self.write_rules({"value": {"type": "integer", "required": True}})
        good = ["0", "-10", "+9", "  001  "]
        bad = ["1.0", "1e2", "１２", "١", "+", "1_000", "1 2", "null"]
        self.write_csv(["value"], [[value] for value in good + bad])
        report, output = self.run_audit()
        self.assertEqual(report["summary"]["rows_clean"], len(good))
        self.assertEqual(report["summary"]["by_code"], {"type": len(bad)})
        self.assertEqual([row[0] for row in self.read_csv(output / "clean.csv")[1:]], good)

    def test_finite_decimal_and_exact_bounds(self):
        self.rules.write_text(
            '{"version":1,"columns":{"value":{"type":"number",'
            '"min":0.10000000000000000001,"max":1.25}}}', encoding="utf-8"
        )
        values = ["0.10000000000000000000", "0.10000000000000000001", " 1.25 ",
                  "1.25000000000000000001", "NaN", "sNaN", "Infinity", "-Inf", "oops"]
        self.write_csv(["value"], [[value] for value in values])
        report, output = self.run_audit()
        self.assertEqual(report["summary"]["by_code"], {"min": 1, "max": 1, "type": 5})
        self.assertEqual(self.read_csv(output / "clean.csv")[1:], [[values[1]], [values[2]]])

    def test_dates_are_exact_calendar_dates(self):
        self.write_rules({"day": {"type": "date", "required": True}})
        good = ["2000-02-29", "2024-02-29", "2025-12-31"]
        bad = ["1900-02-29", "2023-02-29", "2024-02-30", "2024-13-01",
               "2024-2-01", " 2024-01-01", "2024-01-01 ", "0000-01-01"]
        self.write_csv(["day"], [[value] for value in good + bad])
        report, _ = self.run_audit()
        self.assertEqual(report["summary"]["rows_clean"], 3)
        self.assertEqual(report["summary"]["by_code"], {"type": len(bad)})

    def test_rule_source_text_preserves_precision_and_replays_exactly(self):
        raw_rules = (
            b'\xef\xbb\xbf{\r\n  "version": 1,\r\n  "columns": {"value": '
            b'{"type": "number", "min": 0.10000000000000000001}}\r\n}\r\n'
        )
        self.rules.write_bytes(raw_rules)
        self.write_csv(["value"], [["0.1"], ["0.10000000000000000001"]])
        first_report, first_output = self.run_audit()
        self.assertEqual(first_report["summary"]["by_code"], {"min": 1})
        self.assertEqual(first_report["rules"]["source_text"], raw_rules.decode("utf-8-sig"))
        self.assertEqual(first_report["rules"]["sha256"], hashlib.sha256(raw_rules).hexdigest())
        saved_report = json.loads((first_output / "report.json").read_text(encoding="utf-8"))
        self.rules.write_bytes(saved_report["rules"]["source_text"].encode("utf-8"))
        replay_report, replay_output = self.run_audit()
        self.assertEqual(first_report["summary"], replay_report["summary"])
        for name in ("clean.csv", "quarantine.csv", "issues.jsonl"):
            self.assertEqual((first_output / name).read_bytes(), (replay_output / name).read_bytes())

    def test_choices_compare_raw_text(self):
        self.write_rules({"status": {"choices": ["paid", "pending"]}})
        self.write_csv(["status"], [["paid"], [" paid"], ["PAID"], ["\t"]])
        report, _ = self.run_audit()
        self.assertEqual(report["summary"]["by_code"], {"choices": 2})
        self.assertEqual(report["summary"]["rows_clean"], 2)

    def test_duplicates_include_first_and_otherwise_invalid_records(self):
        self.write_rules({"id": {}, "count": {"type": "integer"}}, [["id"]])
        self.write_csv(["id", "count"], [["A", "5"], ["B", "1"], ["A", "bad"]])
        report, output = self.run_audit()
        self.assertEqual(report["summary"], {
            "rows_total": 3, "rows_clean": 1, "rows_quarantined": 2,
            "issues_total": 3, "by_code": {"duplicate": 2, "type": 1},
        })
        duplicates = [i for i in self.read_issues(output) if i["code"] == "duplicate"]
        self.assertEqual([i["row"] for i in duplicates], [1, 3])
        self.assertEqual(duplicates[0]["data"], {"id": "A", "count": "5"})
        self.assertEqual(self.read_csv(output / "clean.csv")[1:], [["B", "1"]])

    def test_composite_keys_are_unambiguous_and_blank_components_skipped(self):
        self.write_rules({"left": {}, "right": {}}, [["left", "right"]])
        rows = [["a|b", "c"], ["a", "b|c"], ["x", "1"], ["x", "1"],
                ["", "1"], ["", "1"], ["x", " "], ["x", " "]]
        self.write_csv(["left", "right"], rows)
        report, output = self.run_audit()
        issues = self.read_issues(output)
        self.assertEqual(report["summary"]["by_code"], {"duplicate": 2})
        self.assertEqual([i["row"] for i in issues], [3, 4])
        self.assertEqual(issues[0]["column"], "left + right")
        self.assertEqual(json.loads(issues[0]["value"]), ["x", "1"])

    def test_unique_uses_raw_text_not_numeric_or_case_normalization(self):
        self.write_rules({"key": {}}, [["key"]])
        values = ["001", "1", "A", "a", "x", " x "]
        self.write_csv(["key"], [[value] for value in values])
        report, _ = self.run_audit()
        self.assertEqual(report["summary"]["rows_clean"], len(values))

    def test_multiple_duplicate_constraints_count_rows_once(self):
        self.write_rules({"a": {}, "b": {}}, [["a"], ["a", "b"]])
        self.write_csv(["a", "b"], [["x", "y"], ["x", "y"]])
        report, _ = self.run_audit()
        self.assertEqual(report["summary"]["issues_total"], 4)
        self.assertEqual(report["summary"]["rows_quarantined"], 2)

    def test_multiline_bom_utf8_provenance_and_column_order(self):
        self.write_rules({"id": {"required": True}, "note": {}}, [["id"]])
        raw = b'\xef\xbb\xbfnote,id\r\n"caf\xc3\xa9\r\nsecond line",A\r\n"<tag> & text",A\r\n'
        self.source.write_bytes(raw)
        report, output = self.run_audit()
        self.assertEqual(report["columns"], ["note", "id"])
        self.assertEqual(report["input"], {
            "name": "data.csv", "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)
        })
        issues = self.read_issues(output)
        self.assertEqual([(i["row"], i["line"]) for i in issues], [(1, 2), (2, 4)])
        self.assertEqual(issues[0]["data"]["note"], "café\r\nsecond line")
        self.assertEqual(self.read_csv(output / "quarantine.csv"), [
            ["note", "id"], ["café\r\nsecond line", "A"], ["<tag> & text", "A"]
        ])
        self.assertEqual(self.source.read_bytes(), raw)

    def test_deterministic_outputs_hashes_and_bounded_preview(self):
        self.write_rules({"id": {}}, [["id"]])
        self.write_csv(["id"], [["A"], ["A"], ["A"]])
        before_rules = self.rules.read_bytes()
        report, first = self.run_audit(preview_limit=1)
        _, second = self.run_audit(preview_limit=1)
        self.assertEqual(len(report["issues_preview"]), 1)
        self.assertEqual(report["summary"]["issues_total"], 3)
        self.assertEqual(len(self.read_issues(first)), 3)
        expected = {"report.json", "issues.jsonl", "clean.csv", "quarantine.csv", "manifest.json"}
        self.assertEqual({path.name for path in first.iterdir()}, expected)
        for name in expected:
            self.assertEqual((first / name).read_bytes(), (second / name).read_bytes())
        manifest = json.loads((first / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["rules"]["sha256"], hashlib.sha256(before_rules).hexdigest())
        for name, digest in manifest["outputs"].items():
            self.assertEqual(digest, hashlib.sha256((first / name).read_bytes()).hexdigest())
        self.assertEqual(self.rules.read_bytes(), before_rules)
        self.assertNotIn(str(self.root), (first / "report.json").read_text(encoding="utf-8"))

    def test_zero_preview_keeps_complete_issue_stream(self):
        self.write_rules({"value": {"required": True}})
        self.write_csv(["value"], [[""]])
        report, output = self.run_audit(preview_limit=0)
        self.assertEqual(report["issues_preview"], [])
        self.assertEqual(len(self.read_issues(output)), 1)

    def test_header_only_file_is_valid(self):
        self.write_rules({"id": {}})
        self.write_csv(["id"], [])
        report, output = self.run_audit()
        self.assertEqual(report["summary"]["rows_total"], 0)
        self.assertEqual(self.read_csv(output / "clean.csv"), [["id"]])
        self.assertEqual(self.read_csv(output / "quarantine.csv"), [["id"]])

    def test_header_ragged_csv_and_encoding_errors_are_fatal(self):
        self.write_rules({"id": {}, "value": {}})
        cases = [b"", b"id,id\n1,2\n", b"id,\n1,2\n", b"id,extra\n1,2\n",
                 b"id\n1\n", b"id,value\n1,2,3\n", b"id,value\n1\n",
                 b'id,value\n1,"unterminated', b'id,value\n1,"bad"suffix\n',
                 b"id,value\n1,ok\n\n", b"id,value\n1,\xff\n"]
        for raw in cases:
            with self.subTest(raw=raw):
                self.source.write_bytes(raw)
                self.assert_fatal()

    def test_configuration_errors_are_rejected_without_results(self):
        self.write_csv(["id"], [["A"]])
        bad = [
            {}, {"version": True, "columns": {"id": {}}},
            {"version": 1.0, "columns": {"id": {}}},
            {"version": 2, "columns": {"id": {}}},
            {"version": 1, "columns": {}},
            {"version": 1, "columns": {"": {}}},
            {"version": 1, "columns": {"id": None}},
            {"version": 1, "columns": {"id": {}}, "extra": True},
            {"version": 1, "columns": {"id": {"unknown": True}}},
            {"version": 1, "columns": {"id": {"type": "float"}}},
            {"version": 1, "columns": {"id": {"required": 1}}},
            {"version": 1, "columns": {"id": {"min": 0}}},
            {"version": 1, "columns": {"id": {"type": "date", "max": 10}}},
            {"version": 1, "columns": {"id": {"type": "number", "min": True}}},
            {"version": 1, "columns": {"id": {"type": "number", "min": "0"}}},
            {"version": 1, "columns": {"id": {"type": "number", "min": 2, "max": 1}}},
            {"version": 1, "columns": {"id": {"type": "integer", "choices": ["1"]}}},
            {"version": 1, "columns": {"id": {"choices": []}}},
            {"version": 1, "columns": {"id": {"choices": [None]}}},
            {"version": 1, "columns": {"id": {}}, "unique": [["missing"]]},
            {"version": 1, "columns": {"id": {}}, "unique": [["id", "id"]]},
            {"version": 1, "columns": {"id": {}}, "unique": [["id"], ["id"]]},
            {"version": 1, "columns": {"id": {}}, "unique": [[]]},
            {"version": 1, "columns": {"id": {}}, "unique": ["id"]},
            {"version": 1, "columns": {"id": {}}, "unique": None},
        ]
        texts = [json.dumps(value) for value in bad] + [
            '{"version":1,"version":1,"columns":{"id":{}}}',
            '{"version":1,"columns":{"id":{"type":"string","type":"string"}}}',
            '{"version":1,"columns":{"id":{"type":"number","min":NaN}}}',
            '{"version":1,"columns":{"id":{"type":"number","min":Infinity}}}',
            '{"version":1,"columns":{"id":{"type":"number","min":1e400}}}',
            '{"version":', '[]',
        ]
        for text in texts:
            with self.subTest(rules=text):
                self.rules.write_text(text, encoding="utf-8")
                self.assert_fatal()

    def test_limits_count_records_and_check_bytes(self):
        self.write_rules({"id": {}})
        self.write_csv(["id"], [["multiline\nvalue"], ["last"]])
        report, _ = self.run_audit(max_rows=2)
        self.assertEqual(report["summary"]["rows_total"], 2)
        self.assert_fatal(max_rows=1)
        self.write_csv(["id"], [["ééé"]])
        with patch.object(rowguard, "MAX_CELL_BYTES", 5):
            self.assert_fatal()
        with patch.object(rowguard, "MAX_INPUT_BYTES", 5):
            self.assert_fatal()
        self.write_rules({"ééé": {}})
        self.write_csv(["ééé"], [["ok"]])
        with patch.object(rowguard, "MAX_CELL_BYTES", 5):
            self.assert_fatal()
        self.write_rules({f"c{index}": {} for index in range(129)})
        self.assert_fatal()

    def test_invalid_runtime_limits(self):
        self.write_rules({"id": {}})
        self.write_csv(["id"], [])
        for kwargs in [{"max_rows": 0}, {"max_rows": 250001}, {"max_rows": True},
                       {"preview_limit": -1}, {"preview_limit": True}]:
            with self.subTest(kwargs=kwargs):
                self.assert_fatal(**kwargs)

    def test_never_overwrites_existing_outputs_or_sources(self):
        self.write_rules({"id": {}})
        self.write_csv(["id"], [["A"]])
        directory = self.root / "existing"
        directory.mkdir()
        sentinel = directory / "keep.txt"
        sentinel.write_text("keep", encoding="utf-8")
        for destination in (directory, self.source, self.rules):
            with self.subTest(destination=destination):
                with self.assertRaises(rowguard.RowGuardError):
                    rowguard.audit(self.source, self.rules, destination)
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "keep")
        report, _ = self.run_audit()
        self.assertEqual(report["summary"]["rows_total"], 1)

    def test_late_failure_cleans_staging_and_publishes_nothing(self):
        self.write_rules({"id": {}})
        self.write_csv(["id"], [["A"]])
        with patch.object(rowguard, "finalize_manifest", side_effect=OSError("disk full")):
            self.assert_fatal()

    def test_output_created_during_run_is_preserved(self):
        self.write_rules({"id": {}})
        self.write_csv(["id"], [["A"]])
        destination = self.root / "raced-output"
        original = rowguard.finalize_manifest

        def create_competing_directory(stage):
            result = original(stage)
            destination.mkdir()
            (destination / "keep.txt").write_text("keep", encoding="utf-8")
            return result

        with patch.object(rowguard, "finalize_manifest", side_effect=create_competing_directory):
            with self.assertRaises(rowguard.RowGuardError):
                rowguard.audit(self.source, self.rules, destination)
        self.assertEqual([path.name for path in destination.iterdir()], ["keep.txt"])
        self.assertFalse(list(self.root.glob(".*.rowguard-*")))

    def test_snapshot_hash_describes_parsed_bytes_if_source_changes_later(self):
        self.write_rules({"id": {}})
        self.write_csv(["id"], [["original"]])
        original_bytes = self.source.read_bytes()
        original_ingest = rowguard._ingest

        def mutate_after_snapshot(*args, **kwargs):
            self.source.write_bytes(b"id\nchanged\n")
            return original_ingest(*args, **kwargs)

        with patch.object(rowguard, "_ingest", side_effect=mutate_after_snapshot):
            report, output = self.run_audit()
        self.assertEqual(report["input"]["sha256"], hashlib.sha256(original_bytes).hexdigest())
        self.assertEqual(self.read_csv(output / "clean.csv")[1:], [["original"]])

    def test_finalize_manifest_includes_html(self):
        self.write_rules({"id": {}})
        self.write_csv(["id"], [["A"]])
        _, output = self.run_audit()
        html = b"<!doctype html><title>Report</title>"
        (output / "index.html").write_bytes(html)
        manifest = rowguard.finalize_manifest(output)
        self.assertEqual(manifest["outputs"]["index.html"], hashlib.sha256(html).hexdigest())

    def test_cli_exit_codes_html_hash_and_atomic_render_failure(self):
        self.write_rules({"id": {"required": True}})
        fake_report = types.ModuleType("report")

        def render_report(report, path):
            Path(path).write_text("<!doctype html><title>Report</title>", encoding="utf-8")
            return Path(path)

        fake_report.render_report = render_report
        with patch.dict(sys.modules, {"report": fake_report}), contextlib.redirect_stdout(io.StringIO()):
            for row, code in ((["A"], 0), ([""], 1)):
                self.write_csv(["id"], [row])
                output = self.root / f"cli-{code}"
                result = rowguard.main([str(self.source), "--rules", str(self.rules),
                                        "--output", str(output)])
                self.assertEqual(result, code)
                manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
                self.assertIn("index.html", manifest["outputs"])
            fake_report.render_report = lambda *_: (_ for _ in ()).throw(OSError("render failed"))
            output = self.root / "render-failed"
            with contextlib.redirect_stderr(io.StringIO()):
                result = rowguard.main([str(self.source), "--rules", str(self.rules),
                                        "--output", str(output)])
            self.assertEqual(result, 2)
            self.assertFalse(output.exists())
            self.assertFalse(list(self.root.glob(".*.rowguard-*")))


if __name__ == "__main__":
    unittest.main()
