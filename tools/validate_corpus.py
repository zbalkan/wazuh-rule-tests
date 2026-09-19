#!/usr/bin/env python3
"""Validate corpus metadata, provenance, and test dependency boundaries."""

from __future__ import annotations

import ast
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "corpus.json"
TESTS = ROOT / "tests"
CORPUS_VERSION = re.compile(r"^(\d+\.\d+\.\d+)-r([1-9]\d*)$")
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


def validate_metadata() -> tuple[dict[str, object], Path]:
    data = load_json(CORPUS)
    required = {
        "schema_version",
        "corpus_version",
        "source_inventory",
        "wazuh",
        "python",
        "wazuhtester",
        "generator",
    }
    missing = sorted(required - data.keys())
    if missing:
        fail(f"corpus.json missing keys: {', '.join(missing)}")
    if data["schema_version"] != 1:
        fail("unsupported corpus schema version")

    version_match = CORPUS_VERSION.fullmatch(str(data["corpus_version"]))
    if not version_match:
        fail("corpus_version must use <wazuh-version>-r<revision>")

    wazuh = data["wazuh"]
    if not isinstance(wazuh, dict):
        fail("wazuh metadata must be an object")
    target = str(wazuh.get("qualification_target", ""))
    if target != version_match.group(1):
        fail("corpus version and Wazuh qualification target must match")
    if wazuh.get("requires") != f"=={target}":
        fail("schema v1 requires exact Wazuh compatibility with the qualification target")
    source_version = str(wazuh.get("source_version", ""))
    if not re.fullmatch(r"\d+\.\d+\.\d+", source_version):
        fail("wazuh source_version must be an explicit semantic version")

    wazuhtester = data["wazuhtester"]
    if not isinstance(wazuhtester, dict) or not wazuhtester.get("requires"):
        fail("wazuhtester compatibility is required")

    generator = data["generator"]
    if not isinstance(generator, dict):
        fail("generator metadata must be an object")
    if generator.get("name") != "wazuh-testgen":
        fail("generator must identify wazuh-testgen")
    if not COMMIT_SHA.fullmatch(str(generator.get("commit", ""))):
        fail("generator commit must be a full Git commit SHA")

    inventory_value = str(data["source_inventory"])
    inventory_path = (ROOT / inventory_value).resolve()
    try:
        inventory_path.relative_to(ROOT)
    except ValueError:
        fail("source_inventory must stay within the repository")
    if not inventory_path.is_file():
        fail(f"source inventory does not exist: {inventory_value}")

    return data, inventory_path


def validate_provenance(
    metadata: dict[str, object],
    inventory_path: Path,
) -> dict[str, str]:
    inventory = load_json(inventory_path)
    if inventory.get("schema_version") != 1:
        fail("unsupported source inventory schema version")

    upstream = inventory.get("upstream")
    if not isinstance(upstream, dict):
        fail("source inventory must contain upstream metadata")

    wazuh = metadata["wazuh"]
    assert isinstance(wazuh, dict)
    target = str(wazuh["qualification_target"])
    source_version = str(wazuh["source_version"])
    if upstream.get("ref") != source_version:
        fail("upstream ref must match the Wazuh source_version")
    if not COMMIT_SHA.fullmatch(str(upstream.get("commit", ""))):
        fail("upstream commit must be a full Git commit SHA")
    if upstream.get("path") != "ruleset/testing/tests":
        fail("unexpected upstream test source path")

    equivalence = inventory.get("equivalent_ruleset_snapshots")
    if not isinstance(equivalence, dict):
        fail("source inventory must contain equivalent_ruleset_snapshots")
    if equivalence.get("scope") != [
        "ruleset/rules",
        "ruleset/decoders",
        "ruleset/testing/tests",
    ]:
        fail("ruleset equivalence scope is incomplete")
    if equivalence.get("file_count") != 395:
        fail("unexpected ruleset equivalence file count")

    snapshots = equivalence.get("snapshots")
    if not isinstance(snapshots, list):
        fail("ruleset equivalence snapshots must be a list")

    snapshot_by_ref: dict[str, str] = {}
    for snapshot in snapshots:
        if not isinstance(snapshot, dict):
            fail("ruleset equivalence snapshot must be an object")
        ref = str(snapshot.get("ref", ""))
        commit = str(snapshot.get("commit", ""))
        if not ref or not COMMIT_SHA.fullmatch(commit):
            fail("ruleset equivalence snapshot must include ref and full commit SHA")
        snapshot_by_ref[ref] = commit

    if target not in snapshot_by_ref:
        fail("qualification target is absent from ruleset equivalence evidence")
    if source_version not in snapshot_by_ref:
        fail("source version is absent from ruleset equivalence evidence")
    if snapshot_by_ref[source_version] != str(upstream.get("commit", "")):
        fail("source-version equivalence commit differs from upstream source commit")

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
    metadata, inventory_path = validate_metadata()
    expected_modules = validate_provenance(metadata, inventory_path)
    validate_tests(expected_modules)
    return 0


if __name__ == "__main__":
    sys.exit(main())
