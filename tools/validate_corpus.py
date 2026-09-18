#!/usr/bin/env python3
"""Validate corpus metadata and test dependency boundaries."""

from __future__ import annotations

import ast
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "corpus.json"
TESTS = ROOT / "tests"
CORPUS_VERSION = re.compile(r"^\d+\.\d+-r[1-9]\d*$")


def fail(message: str) -> None:
    raise SystemExit(f"wazuh-rule-tests: {message}")


def validate_metadata() -> None:
    data = json.loads(CORPUS.read_text(encoding="utf-8"))
    required = {"schema_version", "corpus_version", "wazuh", "python", "wazuhtester", "generator"}
    missing = sorted(required - data.keys())
    if missing:
        fail(f"corpus.json missing keys: {', '.join(missing)}")
    if data["schema_version"] != 1:
        fail("unsupported corpus schema version")
    if not CORPUS_VERSION.fullmatch(str(data["corpus_version"])):
        fail("corpus_version must use <wazuh-series>-r<revision>")
    if not data["wazuh"].get("requires") or not data["wazuh"].get("qualification_target"):
        fail("wazuh compatibility must include requires and qualification_target")
    if not data["wazuhtester"].get("requires"):
        fail("wazuhtester compatibility is required")


def validate_tests() -> None:
    python_files = sorted(TESTS.rglob("*.py"))
    test_files = [path for path in python_files if path.name.startswith("test_")]
    if not test_files:
        fail("no pytest files found")

    forbidden_roots = {"internal", "wazuh_devenv", "wazuhdevenv"}
    for path in python_files:
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except SyntaxError as exc:
            fail(f"{path}: syntax error: {exc}")

        imports_wazuhtester = False
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                roots = {alias.name.split(".", 1)[0] for alias in node.names}
            elif isinstance(node, ast.ImportFrom):
                roots = {node.module.split(".", 1)[0]} if node.module else set()
            else:
                continue

            if roots & forbidden_roots:
                fail(f"{path}: imports repository-internal module(s): {sorted(roots & forbidden_roots)}")
            if "wazuhtester" in roots:
                imports_wazuhtester = True

        if path in test_files and not imports_wazuhtester:
            fail(f"{path}: does not import the public wazuhtester API")

    print(f"Validated {len(test_files)} pytest files and {len(python_files)} Python files.")


def main() -> int:
    validate_metadata()
    validate_tests()
    return 0


if __name__ == "__main__":
    sys.exit(main())
