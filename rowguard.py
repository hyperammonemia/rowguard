"""Validate a local CSV and quarantine every row with a reported issue."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import re
import shutil
import sqlite3
import sys
import tempfile
from datetime import date
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

VERSION = "0.1.0"
MAX_ROWS = 250_000
MAX_INPUT_BYTES = 100 * 1024 * 1024
MAX_COLUMNS = 128
MAX_CELL_BYTES = 1024 * 1024
_INTEGER = re.compile(r"[+-]?[0-9]+\Z")
_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}\Z")
_OUTPUTS = ("report.json", "issues.jsonl", "clean.csv", "quarantine.csv")


class RowGuardError(ValueError):
    """A configuration, input, or output error; no results were published."""


def _json_text(value: Any, *, pretty: bool = False) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        indent=2 if pretty else None,
        separators=None if pretty else (",", ":"),
    )


def _write_json(path: Path, value: Any) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        stream.write(_json_text(value, pretty=True) + "\n")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _snapshot(source: Path, target: Path, *, limit: int | None = None) -> dict:
    digest = hashlib.sha256()
    size = 0
    with source.open("rb") as reader, target.open("xb") as writer:
        for chunk in iter(lambda: reader.read(1024 * 1024), b""):
            size += len(chunk)
            if limit is not None and size > limit:
                raise RowGuardError(f"Input exceeds the {limit}-byte limit.")
            digest.update(chunk)
            writer.write(chunk)
    return {"name": source.name, "sha256": digest.hexdigest(), "bytes": size}


def _object_pairs(pairs: list[tuple[str, Any]]) -> dict:
    result = {}
    for name, value in pairs:
        if name in result:
            raise RowGuardError(f"Duplicate JSON key: {name!r}.")
        result[name] = value
    return result


def _bad_constant(value: str) -> None:
    raise RowGuardError(f"Nonfinite JSON number: {value}.")


def _check_finite(value: Any) -> None:
    if isinstance(value, float) and not math.isfinite(value):
        raise RowGuardError("Rules cannot contain nonfinite numbers.")
    if isinstance(value, dict):
        for item in value.values():
            _check_finite(item)
    elif isinstance(value, list):
        for item in value:
            _check_finite(item)


def _read_rules(path: Path) -> tuple[dict, dict, str]:
    # Preserve source line endings and exact numeric tokens for report replay.
    text = path.read_bytes().decode("utf-8-sig")
    definition = json.loads(
        text, object_pairs_hook=_object_pairs, parse_constant=_bad_constant
    )
    _check_finite(definition)
    # Keep exact decimal thresholds separately from the JSON-compatible report.
    rules = json.loads(
        text,
        object_pairs_hook=_object_pairs,
        parse_float=Decimal,
        parse_constant=_bad_constant,
    )
    if not isinstance(rules, dict):
        raise RowGuardError("Rules must be a JSON object.")
    unknown = rules.keys() - {"version", "columns", "unique"}
    if unknown:
        raise RowGuardError(f"Unknown rule keys: {sorted(unknown)}.")
    if type(rules.get("version")) is not int or rules["version"] != 1:
        raise RowGuardError("Rules version must be the integer 1.")
    columns = rules.get("columns")
    if not isinstance(columns, dict) or not 1 <= len(columns) <= MAX_COLUMNS:
        raise RowGuardError(f"Rules need between 1 and {MAX_COLUMNS} columns.")
    for name, spec in columns.items():
        if not name.strip() or not isinstance(spec, dict):
            raise RowGuardError("Each column needs a nonblank name and an object rule.")
        unknown = spec.keys() - {"type", "required", "min", "max", "choices"}
        if unknown:
            raise RowGuardError(f"Unknown rules for {name!r}: {sorted(unknown)}.")
        kind = spec.get("type", "string")
        if kind not in ("string", "integer", "number", "date"):
            raise RowGuardError(f"Unsupported type for {name!r}.")
        if type(spec.get("required", False)) is not bool:
            raise RowGuardError(f"Required must be boolean for {name!r}.")
        for bound in ("min", "max"):
            if bound in spec:
                value = spec[bound]
                if kind not in ("integer", "number") or type(value) not in (
                    int,
                    Decimal,
                ):
                    raise RowGuardError(f"{bound} must be a numeric bound for {name!r}.")
                spec[bound] = Decimal(value)
                if not spec[bound].is_finite():
                    raise RowGuardError(f"{bound} must be finite for {name!r}.")
        if "min" in spec and "max" in spec and spec["min"] > spec["max"]:
            raise RowGuardError(f"min exceeds max for {name!r}.")
        if "choices" in spec:
            choices = spec["choices"]
            if (
                kind != "string"
                or not isinstance(choices, list)
                or not choices
                or any(not isinstance(choice, str) for choice in choices)
            ):
                raise RowGuardError(f"choices needs a nonempty string list for {name!r}.")
    unique = rules.get("unique", [])
    if not isinstance(unique, list):
        raise RowGuardError("unique must be a list of column lists.")
    seen = set()
    for fields in unique:
        if (
            not isinstance(fields, list)
            or not fields
            or any(not isinstance(field, str) or field not in columns for field in fields)
            or len(set(fields)) != len(fields)
        ):
            raise RowGuardError("Each unique key needs distinct, known column names.")
        key = tuple(fields)
        if key in seen:
            raise RowGuardError("Duplicate unique constraint.")
        seen.add(key)
    rules["unique"] = unique
    return definition, rules, text


def _validate_cell(value: str, spec: dict) -> list[tuple[str, str]]:
    if not value.strip():
        return [("required", "A value is required.")] if spec.get("required") else []
    kind = spec.get("type", "string")
    number = None
    if kind == "integer":
        if not _INTEGER.fullmatch(value.strip()):
            return [("type", "Expected an integer with ASCII digits.")]
        number = Decimal(value.strip())
    elif kind == "number":
        try:
            number = Decimal(value.strip())
        except InvalidOperation:
            return [("type", "Expected a finite decimal number.")]
        if not number.is_finite():
            return [("type", "Expected a finite decimal number.")]
    elif kind == "date":
        try:
            if not _DATE.fullmatch(value):
                raise ValueError
            date.fromisoformat(value)
        except ValueError:
            return [("type", "Expected a valid date in YYYY-MM-DD format.")]
    issues = []
    if number is not None:
        if "min" in spec and number < spec["min"]:
            issues.append(("min", f"Value must be at least {spec['min']}."))
        if "max" in spec and number > spec["max"]:
            issues.append(("max", f"Value must be at most {spec['max']}."))
    if "choices" in spec and value not in spec["choices"]:
        issues.append(("choices", "Value is not one of the allowed choices."))
    return issues


def _create_database(connection: sqlite3.Connection) -> None:
    connection.executescript(
        """
        CREATE TABLE records (id INTEGER PRIMARY KEY, line INTEGER, data TEXT);
        CREATE TABLE issues (
            id INTEGER PRIMARY KEY, row_id INTEGER, column_name TEXT,
            code TEXT, value TEXT, message TEXT
        );
        CREATE INDEX issue_rows ON issues (row_id);
        CREATE TABLE unique_keys (rule_no INTEGER, key TEXT, row_id INTEGER);
        CREATE INDEX key_groups ON unique_keys (rule_no, key);
        """
    )


def _ingest(
    connection: sqlite3.Connection, source: Path, rules: dict, max_rows: int
) -> tuple[list[str], int]:
    count = 0
    previous_limit = csv.field_size_limit(MAX_CELL_BYTES)
    try:
        with source.open("r", encoding="utf-8-sig", newline="") as stream:
            reader = csv.reader(stream, strict=True)
            header = next(reader, None)
            if not header or any(not name.strip() for name in header):
                raise RowGuardError("CSV needs a nonempty header with nonblank names.")
            if len(header) > MAX_COLUMNS or len(header) != len(set(header)):
                raise RowGuardError("CSV has too many columns or duplicate headers.")
            if any(len(name.encode("utf-8")) > MAX_CELL_BYTES for name in header):
                raise RowGuardError("CSV header exceeds the per-cell byte limit.")
            if set(header) != set(rules["columns"]):
                raise RowGuardError("CSV header must contain exactly the rule columns.")
            while True:
                start_line = reader.line_num + 1
                cells = next(reader, None)
                if cells is None:
                    break
                count += 1
                if count > max_rows:
                    raise RowGuardError(f"CSV exceeds the {max_rows}-record limit.")
                if len(cells) != len(header):
                    raise RowGuardError(f"Ragged CSV record {count} at line {start_line}.")
                if any(len(cell.encode("utf-8")) > MAX_CELL_BYTES for cell in cells):
                    raise RowGuardError(f"Record {count} exceeds the per-cell byte limit.")
                data = dict(zip(header, cells))
                connection.execute(
                    "INSERT INTO records VALUES (?, ?, ?)",
                    (count, start_line, _json_text(data)),
                )
                for name, value in data.items():
                    for code, message in _validate_cell(value, rules["columns"][name]):
                        connection.execute(
                            "INSERT INTO issues (row_id, column_name, code, value, message) "
                            "VALUES (?, ?, ?, ?, ?)",
                            (count, name, code, value, message),
                        )
                for rule_no, fields in enumerate(rules["unique"]):
                    values = [data[field] for field in fields]
                    if all(value.strip() for value in values):
                        connection.execute(
                            "INSERT INTO unique_keys VALUES (?, ?, ?)",
                            (rule_no, _json_text(values), count),
                        )
    finally:
        csv.field_size_limit(previous_limit)
    return header, count


def _find_duplicates(connection: sqlite3.Connection, rules: dict) -> None:
    duplicates = connection.execute(
        """
        SELECT keys.rule_no, keys.key, keys.row_id
        FROM unique_keys AS keys
        JOIN (
            SELECT rule_no, key FROM unique_keys
            GROUP BY rule_no, key HAVING COUNT(*) > 1
        ) AS groups USING (rule_no, key)
        ORDER BY keys.rule_no, keys.key, keys.row_id
        """
    )
    for rule_no, key, row_id in duplicates:
        fields = rules["unique"][rule_no]
        label = " + ".join(fields)
        values = json.loads(key)
        value = values[0] if len(values) == 1 else key
        connection.execute(
            "INSERT INTO issues (row_id, column_name, code, value, message) "
            "VALUES (?, ?, ?, ?, ?)",
            (row_id, label, "duplicate", value, f"Duplicate key for {label}."),
        )


def _export(
    connection: sqlite3.Connection, stage: Path, columns: list[str], preview_limit: int
) -> tuple[list[dict], int, dict[str, int]]:
    preview = []
    by_code = dict(
        connection.execute("SELECT code, COUNT(*) FROM issues GROUP BY code ORDER BY code")
    )
    with (stage / "issues.jsonl").open("w", encoding="utf-8", newline="\n") as stream:
        for row, line, column, code, value, message, data in connection.execute(
            "SELECT r.id, r.line, i.column_name, i.code, i.value, i.message, r.data "
            "FROM issues AS i JOIN records AS r ON i.row_id = r.id "
            "ORDER BY r.id, i.id"
        ):
            issue = {
                "row": row,
                "line": line,
                "column": column,
                "code": code,
                "value": value,
                "message": message,
                "data": json.loads(data),
            }
            stream.write(_json_text(issue) + "\n")
            if len(preview) < preview_limit:
                preview.append(issue)
    rejected = 0
    with (
        (stage / "clean.csv").open("w", encoding="utf-8", newline="") as clean,
        (stage / "quarantine.csv").open("w", encoding="utf-8", newline="") as quarantine,
    ):
        writers = (csv.writer(clean), csv.writer(quarantine))
        for writer in writers:
            writer.writerow(columns)
        for data, invalid in connection.execute(
            "SELECT r.data, EXISTS(SELECT 1 FROM issues WHERE row_id = r.id) "
            "FROM records AS r ORDER BY r.id"
        ):
            cells = json.loads(data)
            writers[invalid].writerow([cells[column] for column in columns])
            rejected += invalid
    return preview, rejected, by_code


def finalize_manifest(output_dir: str | Path) -> dict:
    """Refresh output hashes after adding an HTML report or demo metadata."""
    root = Path(output_dir)
    report = json.loads((root / "report.json").read_text(encoding="utf-8"))
    names = list(_OUTPUTS)
    if (root / "index.html").is_file():
        names.append("index.html")
    manifest = {
        "schema_version": 1,
        "tool_version": VERSION,
        "input": report["input"],
        "rules": {key: report["rules"][key] for key in ("name", "sha256")},
        "outputs": {name: _sha256(root / name) for name in sorted(names)},
    }
    # A refresh either replaces the complete manifest or leaves its previous copy.
    handle, temporary = tempfile.mkstemp(prefix=".manifest-", dir=root)
    os.close(handle)
    try:
        _write_json(Path(temporary), manifest)
        os.replace(temporary, root / "manifest.json")
    finally:
        Path(temporary).unlink(missing_ok=True)
    return manifest


def _new_stage(output_dir: Path) -> Path:
    if os.path.lexists(output_dir):
        raise RowGuardError("Output already exists; choose a new output directory.")
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    return Path(tempfile.mkdtemp(prefix=f".{output_dir.name}.rowguard-", dir=output_dir.parent))


def _publish(stage: Path, output_dir: Path) -> None:
    if os.path.lexists(output_dir):
        raise RowGuardError("Output appeared during validation; refusing to overwrite it.")
    os.rename(stage, output_dir)


def audit(
    csv_path: str | Path,
    rules_path: str | Path,
    output_dir: str | Path,
    *,
    preview_limit: int = 200,
    max_rows: int = MAX_ROWS,
) -> dict:
    """Validate snapshots of the sources and atomically publish complete outputs."""
    if type(preview_limit) is not int or preview_limit < 0:
        raise RowGuardError("preview_limit must be a nonnegative integer.")
    if type(max_rows) is not int or not 1 <= max_rows <= MAX_ROWS:
        raise RowGuardError(f"max_rows must be between 1 and {MAX_ROWS}.")
    destination = Path(output_dir)
    stage = None
    try:
        stage = _new_stage(destination)
        input_copy, rules_copy = stage / ".input.csv", stage / ".rules.json"
        input_info = _snapshot(Path(csv_path), input_copy, limit=MAX_INPUT_BYTES)
        rules_info = _snapshot(Path(rules_path), rules_copy)
        definition, rules, rules_text = _read_rules(rules_copy)
        database = stage / ".rows.sqlite3"
        connection = sqlite3.connect(database)
        try:
            _create_database(connection)
            with connection:
                columns, total = _ingest(connection, input_copy, rules, max_rows)
                _find_duplicates(connection, rules)
            preview, rejected, by_code = _export(connection, stage, columns, preview_limit)
        finally:
            connection.close()
        report = {
            "schema_version": 1,
            "tool_version": VERSION,
            "input": input_info,
            "rules": {
                "name": rules_info["name"],
                "sha256": rules_info["sha256"],
                "definition": definition,
                "source_text": rules_text,
            },
            "columns": columns,
            "summary": {
                "rows_total": total,
                "rows_clean": total - rejected,
                "rows_quarantined": rejected,
                "issues_total": sum(by_code.values()),
                "by_code": by_code,
            },
            "preview_limit": preview_limit,
            "issues_preview": preview,
        }
        _write_json(stage / "report.json", report)
        for temporary in (input_copy, rules_copy, database):
            temporary.unlink()
        finalize_manifest(stage)
        _publish(stage, destination)
        return report
    except (OSError, UnicodeError, csv.Error, sqlite3.Error, json.JSONDecodeError) as exc:
        raise RowGuardError(f"Unable to complete validation: {exc}") from exc
    finally:
        if stage is not None and stage.exists():
            shutil.rmtree(stage)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="version", version=f"RowGuard {VERSION}")
    parser.add_argument("csv_path", type=Path)
    parser.add_argument("--rules", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--preview-limit", type=int, default=200)
    parser.add_argument("--max-rows", type=int, default=MAX_ROWS)
    arguments = parser.parse_args(argv)
    stage = None
    try:
        stage = _new_stage(arguments.output)
        payload = stage / "results"
        result = audit(
            arguments.csv_path,
            arguments.rules,
            payload,
            preview_limit=arguments.preview_limit,
            max_rows=arguments.max_rows,
        )
        from report import render_report

        render_report(result, payload / "index.html")
        finalize_manifest(payload)
        _publish(payload, arguments.output)
        summary = result["summary"]
        print(
            f"{summary['rows_total']} rows: {summary['rows_clean']} clean, "
            f"{summary['rows_quarantined']} quarantined. Report: "
            f"{arguments.output / 'index.html'}"
        )
        return 1 if summary["rows_quarantined"] else 0
    except Exception as exc:
        print(f"RowGuard: {exc}", file=sys.stderr)
        return 2
    finally:
        if stage is not None and stage.exists():
            shutil.rmtree(stage)


if __name__ == "__main__":
    raise SystemExit(main())
