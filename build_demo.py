"""Rebuild the published synthetic example, or check it without changing files."""
import argparse
import csv
import json
from pathlib import Path
import shutil
import tempfile

from rowguard import audit, finalize_manifest
from report import render_report

ROOT = Path(__file__).resolve().parent
ARTIFACTS = ("report.json", "issues.jsonl", "clean.csv", "quarantine.csv", "index.html", "manifest.json")


def build_demo(check=False):
    expected = json.loads((ROOT / "data/expected.json").read_text(encoding="utf-8"))
    scratch = ROOT / ".tmp"
    scratch.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="demo-", dir=scratch) as temporary:
        destination = Path(temporary) / "audit"
        result = audit(ROOT / "data/orders.csv", ROOT / "data/rules.json", destination)
        for key in ("rows_total", "rows_clean", "rows_quarantined", "issues_total", "by_code"):
            assert result["summary"][key] == expected[key], f"Unexpected demo {key}"
        issue_rows = {item["row"] for item in result["issues_preview"]}
        assert issue_rows == set(expected["quarantined_records"])
        with (ROOT / "data/orders.csv").open(encoding="utf-8-sig", newline="") as stream:
            original = list(csv.reader(stream))
        rejected = set(expected["quarantined_records"])
        for filename, is_rejected in [("clean.csv", False), ("quarantine.csv", True)]:
            with (destination / filename).open(encoding="utf-8-sig", newline="") as stream:
                actual = list(csv.reader(stream))
            wanted = [original[0]] + [row for index, row in enumerate(original[1:], 1)
                                      if (index in rejected) == is_rejected]
            assert actual == wanted, f"{filename} changed original cell values or row order"
        result["demo"] = {
            "synthetic": True,
            "description": "合成订单演示：200 条记录中人工植入错误；不含真实客户或交易数据。",
            "expected_quarantined_rows": expected["quarantined_records"],
        }
        (destination / "report.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
        render_report(result, destination / "index.html")
        finalize_manifest(destination)
        for name in ARTIFACTS:
            assert (destination / name).is_file(), name
            for folder in (ROOT / "output", ROOT / "docs"):
                target = folder / name
                if check:
                    assert target.read_bytes() == (destination / name).read_bytes(), f"Rebuild differs: {target}"
                else:
                    folder.mkdir(exist_ok=True)
                    shutil.copyfile(destination / name, target)
    print("Demo verified: 200 records; 189 clean, 11 quarantined, 12 issues."
          + (" Published files reproduce byte-for-byte." if check else ""))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    build_demo(parser.parse_args().check)
