"""Read-only verification of generated results, sources, and damaged bundles."""

import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import rowguard
import rowguard_verify


class VerificationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "source.csv"
        self.rules = self.root / "rules.json"
        self.output = self.root / "result"
        self.source.write_bytes(
            b'\xef\xbb\xbfid,value\r\nA,"caf\xc3\xa9\r\nline"\r\nA,x\r\nB,y\r\n'
        )
        self.rules.write_bytes(
            b'{"version":1,"columns":{"id":{},"value":{}},"unique":[["id"]]}'
        )
        rowguard.audit(self.source, self.rules, self.output)
        self.manifest_path = self.output / "manifest.json"
        self.manifest = json.loads(self.manifest_path.read_text(encoding="utf-8"))

    def write_manifest(self, manifest):
        self.manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    def verify(self):
        return rowguard_verify.verify(
            self.output, input_path=self.source, rules_path=self.rules
        )

    def snapshot(self):
        return {
            path.relative_to(self.root).as_posix(): path.read_bytes()
            for path in self.root.rglob("*")
            if path.is_file()
        }

    def test_generated_results_match_without_writing_and_repeat_exactly(self):
        before = self.snapshot()
        result = self.verify()
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(result["status"], "match")
        self.assertEqual(
            result["manifest"]["sha256"],
            hashlib.sha256(before["result/manifest.json"]).hexdigest(),
        )
        self.assertEqual(
            {item["status"] for item in result["outputs"].values()}, {"match"}
        )
        self.assertEqual(
            result["sources"]["input"]["actual_bytes"], len(self.source.read_bytes())
        )
        self.assertEqual(result["sources"]["rules"]["status"], "match")
        self.assertEqual(self.verify(), result)
        self.assertEqual(self.snapshot(), before)
        self.assertNotIn(str(self.root), json.dumps(result))

    def test_omitted_sources_are_unchecked_even_if_originals_are_missing(self):
        self.source.unlink()
        self.rules.unlink()
        result = rowguard_verify.verify(self.output)
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(
            {item["status"] for item in result["sources"].values()}, {"unchecked"}
        )
        self.assertIn("not authorship or authenticity", result["notice"])
        requested = self.verify()
        self.assertEqual(requested["exit_code"], 1)
        self.assertEqual(
            {item["status"] for item in requested["sources"].values()}, {"missing"}
        )

    def test_moved_bundle_and_renamed_sources_match_by_bytes(self):
        moved = self.root / "moved"
        self.output.rename(moved)
        renamed = self.root / "renamed.csv"
        self.source.rename(renamed)
        result = rowguard_verify.verify(
            moved, input_path=renamed, rules_path=self.rules
        )
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(result["sources"]["input"]["status"], "match")

    def test_changed_and_missing_outputs_are_reported_together(self):
        (self.output / "clean.csv").write_bytes(b"changed")
        (self.output / "issues.jsonl").unlink()
        result = self.verify()
        self.assertEqual(result["exit_code"], 1)
        self.assertEqual(result["outputs"]["clean.csv"]["status"], "changed")
        self.assertEqual(result["outputs"]["issues.jsonl"]["status"], "missing")
        self.assertEqual(result["outputs"]["report.json"]["status"], "match")
        self.assertEqual(result["sources"]["input"]["status"], "match")

    def test_wrong_sources_and_input_byte_count_are_detected(self):
        self.source.write_bytes(self.source.read_bytes().replace(b"B,y", b"C,y"))
        self.rules.write_bytes(self.rules.read_bytes() + b" ")
        result = self.verify()
        self.assertEqual(result["exit_code"], 1)
        self.assertEqual(
            {item["status"] for item in result["sources"].values()}, {"changed"}
        )
        self.manifest["input"]["sha256"] = hashlib.sha256(
            self.source.read_bytes()
        ).hexdigest()
        self.manifest["rules"]["sha256"] = hashlib.sha256(
            self.rules.read_bytes()
        ).hexdigest()
        self.manifest["input"]["bytes"] += 1
        self.write_manifest(self.manifest)
        count_only = self.verify()
        self.assertEqual(count_only["exit_code"], 1)
        self.assertEqual(count_only["sources"]["input"]["status"], "changed")
        self.assertEqual(
            count_only["sources"]["input"]["actual_sha256"],
            self.manifest["input"]["sha256"],
        )

    def test_html_is_checked_when_listed_and_flagged_when_unlisted(self):
        html = self.output / "index.html"
        html.write_bytes(b"<!doctype html><title>Report</title>")
        result = self.verify()
        self.assertEqual(result["exit_code"], 1)
        self.assertEqual(result["outputs"]["index.html"]["status"], "unlisted")
        rowguard.finalize_manifest(self.output)
        self.assertEqual(self.verify()["outputs"]["index.html"]["status"], "match")
        html.write_bytes(b"changed")
        self.assertEqual(self.verify()["outputs"]["index.html"]["status"], "changed")
        html.unlink()
        self.assertEqual(self.verify()["outputs"]["index.html"]["status"], "missing")

    def test_unrelated_bundle_files_are_outside_verification_scope(self):
        (self.output / ".nojekyll").write_bytes(b"")
        (self.output / "notes.txt").write_bytes(b"not part of the results")
        result = self.verify()
        self.assertEqual(result["exit_code"], 0)
        self.assertNotIn("notes.txt", result["outputs"])

    def test_v010_manifest_is_accepted(self):
        self.manifest["tool_version"] = "0.1.0"
        self.write_manifest(self.manifest)
        result = self.verify()
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(result["manifest"]["producer_version"], "0.1.0")

    def test_invalid_manifest_schemas_never_read_named_outputs(self):
        bad = []
        for key, value in [
            ("schema_version", True),
            ("schema_version", 1.0),
            ("schema_version", 2),
            ("tool_version", ""),
            ("tool_version", 1),
            ("outputs", []),
            ("input", None),
        ]:
            candidate = json.loads(json.dumps(self.manifest))
            candidate[key] = value
            bad.append(candidate)
        for label, key, value in [
            ("input", "bytes", True),
            ("input", "bytes", -1),
            ("input", "bytes", 1.5),
            ("input", "name", ""),
            ("rules", "sha256", "a" * 63),
            ("rules", "sha256", "G" * 64),
        ]:
            candidate = json.loads(json.dumps(self.manifest))
            candidate[label][key] = value
            bad.append(candidate)
        for name in (
            "../outside.txt",
            "C:\\outside.txt",
            "/outside.txt",
            "sub/file.txt",
            "report.json/../outside.txt",
        ):
            candidate = json.loads(json.dumps(self.manifest))
            candidate["outputs"][name] = "a" * 64
            bad.append(candidate)
        candidate = json.loads(json.dumps(self.manifest))
        del candidate["outputs"]["clean.csv"]
        bad.extend([candidate, [], None])
        for value in bad:
            with self.subTest(manifest=value):
                self.write_manifest(value)
                with patch.object(
                    rowguard_verify,
                    "_hash_file",
                    side_effect=AssertionError("must not hash"),
                ):
                    result = self.verify()
                self.assertEqual(result["exit_code"], 2)
                self.assertEqual(result["outputs"], {})

    def test_duplicate_keys_invalid_json_and_oversize_manifest(self):
        texts = [
            '{"schema_version":1,"schema_version":1}',
            '{"schema_version":NaN}',
            '{"schema_version":Infinity}',
            "{",
            '{"outputs":{"clean.csv":"a","clean.csv":"b"}}',
        ]
        for text in texts:
            with self.subTest(text=text):
                self.manifest_path.write_text(text, encoding="utf-8")
                self.assertEqual(self.verify()["exit_code"], 2)
        self.manifest_path.write_bytes(b" " * (rowguard_verify.MAX_MANIFEST_BYTES + 1))
        self.assertEqual(self.verify()["exit_code"], 2)

    def test_missing_manifest_and_nondirectory_are_errors(self):
        self.manifest_path.unlink()
        result = self.verify()
        self.assertEqual(result["exit_code"], 2)
        self.assertNotIn(str(self.root), json.dumps(result))
        self.assertEqual(rowguard_verify.verify(self.source)["exit_code"], 2)
        self.assertEqual(rowguard_verify.verify(self.root / "missing")["exit_code"], 2)

    def test_nonregular_output_and_read_error_keep_other_results(self):
        target = self.output / "clean.csv"
        target.unlink()
        target.mkdir()
        result = self.verify()
        self.assertEqual(result["exit_code"], 2)
        self.assertEqual(result["outputs"]["clean.csv"]["status"], "error")
        self.assertEqual(result["outputs"]["report.json"]["status"], "match")
        original = rowguard_verify._hash_file

        def deny_report(path):
            if path.name == "report.json":
                raise PermissionError(13, "Permission denied", str(path))
            return original(path)

        with patch.object(rowguard_verify, "_hash_file", side_effect=deny_report):
            result = self.verify()
        self.assertEqual(result["outputs"]["report.json"]["status"], "error")
        self.assertNotIn(str(self.root), json.dumps(result))

    def test_root_symlink_loop_returns_cli_json_error(self):
        first, second = self.root / "loop-a", self.root / "loop-b"
        try:
            first.symlink_to(second, target_is_directory=True)
            second.symlink_to(first, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("Creating symlinks is unavailable for this account.")
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            code = rowguard_verify.main([str(first)])
        result = json.loads(stream.getvalue())
        self.assertEqual(code, 2)
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["outputs"], {})
        self.assertNotIn(str(self.root), stream.getvalue())

    def test_python310_resolve_loop_exception_has_portable_diagnostics(self):
        # Older pathlib versions raise RuntimeError, including an absolute path.
        stream = io.StringIO()
        with patch.object(
            Path,
            "resolve",
            side_effect=RuntimeError(f"Symlink loop from {self.output}"),
        ):
            with contextlib.redirect_stdout(stream):
                code = rowguard_verify.main([str(self.output)])
        result = json.loads(stream.getvalue())
        self.assertEqual(code, 2)
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["outputs"], {})
        self.assertIn("symlink loop", result["manifest"]["message"])
        self.assertNotIn(str(self.root), stream.getvalue())

    def test_output_symlinks_including_dangling_are_rejected_without_reading(self):
        probe = self.root / "link-probe"
        try:
            probe.symlink_to(self.source)
        except (OSError, NotImplementedError):
            self.skipTest("Creating symlinks is unavailable for this account.")
        probe.unlink()
        target = self.output / "clean.csv"
        target.unlink()
        target.symlink_to(self.source)
        result = self.verify()
        self.assertEqual(result["exit_code"], 2)
        self.assertEqual(result["outputs"]["clean.csv"]["status"], "error")
        self.assertNotIn("actual_sha256", result["outputs"]["clean.csv"])
        target.unlink()
        target.symlink_to(self.root / "missing")
        self.assertEqual(self.verify()["outputs"]["clean.csv"]["status"], "error")
        target.unlink()
        external_manifest = self.root / "manifest-original.json"
        self.manifest_path.rename(external_manifest)
        self.manifest_path.symlink_to(external_manifest)
        self.assertEqual(self.verify()["exit_code"], 2)

    @unittest.skipUnless(
        hasattr(os, "mkfifo"), "Named pipes are not available on this platform."
    )
    def test_fifo_output_is_rejected_without_blocking(self):
        target = self.output / "clean.csv"
        target.unlink()
        os.mkfifo(target)
        result = self.verify()
        self.assertEqual(result["exit_code"], 2)
        self.assertEqual(result["outputs"]["clean.csv"]["status"], "error")

    def test_cli_returns_json_and_exit_codes(self):
        def run():
            stream = io.StringIO()
            with contextlib.redirect_stdout(stream):
                code = rowguard_verify.main(
                    [
                        str(self.output),
                        "--input",
                        str(self.source),
                        "--rules",
                        str(self.rules),
                    ]
                )
            result = json.loads(stream.getvalue())
            self.assertEqual(code, result["exit_code"])
            return code

        self.assertEqual(run(), 0)
        self.source.write_bytes(b"changed")
        self.assertEqual(run(), 1)
        self.manifest_path.write_bytes(b"not json")
        self.assertEqual(run(), 2)

    def test_module_cli_checks_real_generated_bundle(self):
        process = subprocess.run(
            [sys.executable, "-m", "rowguard_verify", str(self.output)],
            capture_output=True,
            text=True,
            cwd=Path(rowguard.__file__).parent,
        )
        self.assertEqual(process.returncode, 0, process.stderr)
        result = json.loads(process.stdout)
        self.assertEqual(result["status"], "match")
        self.assertEqual(result["sources"]["input"]["status"], "unchecked")


if __name__ == "__main__":
    unittest.main()
