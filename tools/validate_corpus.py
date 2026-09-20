#!/usr/bin/env python3
"""Validate the corpus source inventory and test dependency boundaries."""

from __future__ import annotations

import ast
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "corpus.json"
INVENTORY = ROOT / "source" / "inventory.json"
TESTS = ROOT / "tests"
VERSION = re.compile(r"^\d+\.\d+\.\d+$")
COMMIT_SHA = re.compile(r"^[0-9a-f]{40}$")
INVALID_IDENTIFIER_CHARS = re.compile(r"[^0-9A-Za-z_]+")
REPEATED_UNDERSCORES = re.compile(r"_+")


def fail(message: str) -> None:
    raise SystemExit(f"wazuh-rule-tests: {message}")


def identifier(value: str) -> str:
    value = INVALID_IDENTIFIER_CHARS.sub("_", value)
    value = REPEATED_UNDERSCORES.sub("_", value).strip("_").lower()
    if not value:
        return "case"
    if value[0].isdigit():
        return f"case_{value}"
    return value


def load_json(path: Path) -> dict[str, object]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"cannot read {path.relative_to(ROOT)}: {exc}")
    if not isinstance(data, dict):
        fail(f"{path.relative_to(ROOT)} must contain a JSON object")
    return data


def validate_metadata() -> None:
    metadata = load_json(CORPUS)
    version = metadata.get("version")
    if not isinstance(version, str) or not VERSION.fullmatch(version):
        fail("version must use X.Y.Z")


def validate_inventory() -> dict[str, str]:
    inventory = load_json(INVENTORY)

    upstream = inventory.get("upstream")
    if not isinstance(upstream, dict):
        fail("source inventory must contain upstream metadata")
    if not isinstance(upstream.get("repository"), str) or not upstream["repository"]:
        fail("upstream repository is required")
    if not COMMIT_SHA.fullmatch(str(upstream.get("commit", ""))):
        fail("upstream commit must be a full Git commit SHA")
    if not isinstance(upstream.get("path"), str) or not upstream["path"]:
        fail("upstream path is required")

    generator = inventory.get("generator")
    if not isinstance(generator, dict):
        fail("source inventory must contain generator metadata")
    if not isinstance(generator.get("repository"), str) or not generator["repository"]:
        fail("generator repository is required")
    if not COMMIT_SHA.fullmatch(str(generator.get("commit", ""))):
        fail("generator commit must be a full Git commit SHA")

    source_files = inventory.get("source_files")
    excluded = inventory.get("excluded")
    if not isinstance(source_files, list) or not all(
        isinstance(name, str) and name.endswith(".ini") for name in source_files
    ):
        fail("source_files must be a list of INI filenames")
    if len(source_files) != len(set(source_files)):
        fail("source_files contains duplicate filenames")
    if not isinstance(excluded, dict) or not all(
        isinstance(name, str)
        and isinstance(reason, str)
        and reason.strip()
        for name, reason in excluded.items()
    ):
        fail("excluded must map INI filenames to non-empty reasons")

    unknown_exclusions = sorted(set(excluded) - set(source_files))
    if unknown_exclusions:
        fail(f"excluded files are absent from source inventory: {', '.join(unknown_exclusions)}")

    included = [name for name in source_files if name not in excluded]
    expected_modules: dict[str, str] = {}
    for source_name in included:
        module = f"test_{identifier(Path(source_name).stem)}_rules.py"
        previous = expected_modules.get(module)
        if previous:
            fail(
                f"source filename collision: {previous} and {source_name} both map to {module}"
            )
        expected_modules[module] = source_name

    actual_modules = {
        path.name
        for path in TESTS.glob("test_*.py")
        if path.is_file()
    }
    expected_names = set(expected_modules)

    missing = sorted(expected_names - actual_modules)
    extra = sorted(actual_modules - expected_names)
    if missing:
        fail(f"missing generated modules: {', '.join(missing)}")
    if extra:
        fail(f"generated modules without source INI: {', '.join(extra)}")

    for module, source_name in expected_modules.items():
        text = (TESTS / module).read_text(encoding="utf-8")
        marker = f"# Converted from {source_name}"
        if marker not in text:
            fail(f"{module}: missing provenance marker {marker!r}")

    print(
        "Validated source inventory: "
        f"{len(source_files)} upstream INIs = "
        f"{len(expected_modules)} generated modules + {len(excluded)} exclusions."
    )
    return expected_modules


def validate_tests(expected_modules: dict[str, str]) -> None:
    python_files = sorted(TESTS.rglob("*.py"))
    test_files = [path for path in python_files if path.name in expected_modules]
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
                fail(
                    f"{path}: imports repository-internal module(s): "
                    f"{sorted(roots & forbidden_roots)}"
                )
            if "wazuhtester" in roots:
                imports_wazuhtester = True

        if path in test_files and not imports_wazuhtester:
            fail(f"{path}: does not import the public wazuhtester API")

    print(f"Validated {len(test_files)} generated pytest modules.")


def main() -> int:
    validate_metadata()
    expected_modules = validate_inventory()
    validate_tests(expected_modules)
    return 0


if __name__ == "__main__":
    sys.exit(main())
