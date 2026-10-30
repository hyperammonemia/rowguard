"""Check RowGuard result files against a supplied manifest without modifying them."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import BinaryIO, Iterator

from rowguard import VERSION

REQUIRED_OUTPUTS = frozenset(
    ("report.json", "issues.jsonl", "clean.csv", "quarantine.csv")
)
ALLOWED_OUTPUTS = REQUIRED_OUTPUTS | {"index.html"}
MAX_MANIFEST_BYTES = 1024 * 1024
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
NOTICE = (
    "Checks byte consistency against the supplied manifest, not authorship or authenticity. "
    "Trust the manifest separately. Only listed outputs and the optional HTML report are "
    "covered; omitted source paths remain unchecked."
)


class ManifestError(ValueError):
    """The supplied file is not a supported RowGuard manifest."""


def _pairs(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ManifestError(f"Duplicate JSON key: {key!r}.")
        result[key] = value
    return result


def _constant(value: str) -> None:
    raise ManifestError(f"Invalid JSON constant: {value}.")


def _object(value: object, keys: set[str], label: str) -> dict:
    if not isinstance(value, dict) or set(value) != keys:
        raise ManifestError(f"{label} must contain exactly: {', '.join(sorted(keys))}.")
    return value


def _digest(value: object, label: str) -> None:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise ManifestError(f"{label} must be a lowercase SHA256 digest.")


def _validate_manifest(value: object) -> dict:
    manifest = _object(
        value,
        {"schema_version", "tool_version", "input", "rules", "outputs"},
        "Manifest",
    )
    if type(manifest["schema_version"]) is not int or manifest["schema_version"] != 1:
        raise ManifestError("Unsupported manifest schema; expected integer version 1.")
    if (
        not isinstance(manifest["tool_version"], str)
        or not manifest["tool_version"].strip()
    ):
        raise ManifestError("tool_version must be a nonblank string.")
    for label in ("input", "rules"):
        keys = {"name", "sha256", "bytes"} if label == "input" else {"name", "sha256"}
        source = _object(manifest[label], keys, label)
        if not isinstance(source["name"], str) or not source["name"].strip():
            raise ManifestError(f"{label}.name must be a nonblank string.")
        _digest(source["sha256"], f"{label}.sha256")
        if label == "input" and (
            type(source["bytes"]) is not int or source["bytes"] < 0
        ):
            raise ManifestError("input.bytes must be a nonnegative integer.")
    outputs = manifest["outputs"]
    if not isinstance(outputs, dict):
        raise ManifestError("outputs must be an object.")
    if not REQUIRED_OUTPUTS <= outputs.keys() or not outputs.keys() <= ALLOWED_OUTPUTS:
        raise ManifestError(
            "outputs must list the four core files and may also list index.html."
        )
    for name, digest in outputs.items():
        _digest(digest, f"outputs.{name}")
    return manifest


def _is_link(info: os.stat_result) -> bool:
    # On Windows this also rejects reparse points that are not reported as symlinks.
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & 0x400
    )


@contextmanager
def _open_regular(path: Path) -> Iterator[BinaryIO]:
    info = path.lstat()
    if _is_link(info) or not stat.S_ISREG(info.st_mode):
        raise OSError("Refusing a link or nonregular file.")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as stream:
        opened = os.fstat(stream.fileno())
        if not stat.S_ISREG(opened.st_mode) or (info.st_dev, info.st_ino) != (
            opened.st_dev,
            opened.st_ino,
        ):
            raise OSError("File changed while opening it; retry with stable files.")
        yield stream


def _hash_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with _open_regular(path) as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def _message(error: Exception) -> str:
    # OS errors can include private absolute paths; report the reason only.
    return (
        error.strerror if isinstance(error, OSError) and error.strerror else str(error)
    )


def _check_file(path: Path, expected: str, expected_bytes: int | None = None) -> dict:
    result = {"expected_sha256": expected}
    if expected_bytes is not None:
        result["expected_bytes"] = expected_bytes
    try:
        digest, size = _hash_file(path)
        result.update(actual_sha256=digest, actual_bytes=size)
        result["status"] = (
            "match"
            if digest == expected and (expected_bytes is None or size == expected_bytes)
            else "changed"
        )
    except FileNotFoundError:
        result.update(status="missing", message="File is missing.")
    except OSError as exc:
        result.update(status="error", message=_message(exc))
    return result


def verify(
    output_dir: str | Path,
    *,
    input_path: str | Path | None = None,
    rules_path: str | Path | None = None,
) -> dict:
    """Return read-only checksum diagnostics; exit_code is 0, 1, or 2.

    Use a trusted, stable manifest and files. This is not signature verification,
    a validation rerun, or a snapshot of a directory being modified concurrently.
    Explicit source paths are compared by bytes, regardless of their current names.
    """
    result = {
        "schema_version": 1,
        "tool_version": VERSION,
        "status": "error",
        "exit_code": 2,
        "notice": NOTICE,
        "manifest": {"status": "error"},
        "outputs": {},
        "sources": {"input": {"status": "unchecked"}, "rules": {"status": "unchecked"}},
    }
    try:
        try:
            root = Path(output_dir).resolve(strict=True)
        except RuntimeError as exc:
            # Python 3.10 reports symlink loops as RuntimeError, unlike newer versions.
            raise OSError(
                "Unable to resolve output directory (possible symlink loop)."
            ) from exc
        if not root.is_dir():
            raise OSError("Output path must be a directory.")
        with _open_regular(root / "manifest.json") as stream:
            raw = stream.read(MAX_MANIFEST_BYTES + 1)
        if len(raw) > MAX_MANIFEST_BYTES:
            raise ManifestError("Manifest exceeds the 1 MiB limit.")
        manifest = _validate_manifest(
            json.loads(
                raw.decode("utf-8-sig"),
                object_pairs_hook=_pairs,
                parse_constant=_constant,
            )
        )
    except (OSError, ValueError, UnicodeError, RecursionError) as exc:
        result["manifest"]["message"] = _message(exc)
        return result
    result["manifest"] = {
        "status": "valid",
        "sha256": hashlib.sha256(raw).hexdigest(),
        "producer_version": manifest["tool_version"],
    }
    for name, digest in sorted(manifest["outputs"].items()):
        result["outputs"][name] = _check_file(root / name, digest)
    if "index.html" not in manifest["outputs"]:
        try:
            (root / "index.html").lstat()
        except FileNotFoundError:
            pass
        except OSError as exc:
            result["outputs"]["index.html"] = {
                "status": "error",
                "message": _message(exc),
            }
        else:
            result["outputs"]["index.html"] = {
                "status": "unlisted",
                "message": "HTML report exists but is absent from the manifest.",
            }
    for label, path in (("input", input_path), ("rules", rules_path)):
        source = manifest[label]
        if path is None:
            result["sources"][label] = {
                "status": "unchecked",
                "expected_sha256": source["sha256"],
            }
            if label == "input":
                result["sources"][label]["expected_bytes"] = source["bytes"]
        else:
            result["sources"][label] = _check_file(
                Path(path), source["sha256"], source.get("bytes")
            )
    statuses = {
        item["status"]
        for item in (*result["outputs"].values(), *result["sources"].values())
    }
    code = (
        2
        if "error" in statuses
        else 1 if statuses & {"changed", "missing", "unlisted"} else 0
    )
    result.update(exit_code=code, status={0: "match", 1: "mismatch", 2: "error"}[code])
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, epilog=NOTICE)
    parser.add_argument("output_dir", type=Path)
    parser.add_argument(
        "--input",
        type=Path,
        dest="input_path",
        help="Original CSV to compare; otherwise unchecked.",
    )
    parser.add_argument(
        "--rules",
        type=Path,
        dest="rules_path",
        help="Original rules file to compare; otherwise unchecked.",
    )
    parser.add_argument("--version", action="version", version=f"RowGuard {VERSION}")
    args = parser.parse_args(argv)
    result = verify(
        args.output_dir, input_path=args.input_path, rules_path=args.rules_path
    )
    print(json.dumps(result, ensure_ascii=True, sort_keys=True, indent=2))
    return result["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
