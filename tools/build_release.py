#!/usr/bin/env python3
"""Build the wazuh-rule-tests release archive and manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import zipfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INVENTORY = ROOT / "source" / "inventory.json"


def build_timestamp() -> str:
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if epoch:
        value = datetime.fromtimestamp(int(epoch), tz=timezone.utc)
    else:
        value = datetime.now(timezone.utc)
    return value.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def zip_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o644 << 16
    return info


def write_bytes(archive: zipfile.ZipFile, name: str, content: bytes) -> None:
    archive.writestr(zip_info(name), content)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--commit", required=True, help="Repository commit represented by the archive")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "dist")
    args = parser.parse_args()

    metadata = json.loads((ROOT / "corpus.json").read_text(encoding="utf-8"))
    inventory_bytes = INVENTORY.read_bytes()
    inventory = json.loads(inventory_bytes)
    excluded = inventory["excluded"]
    source_files = inventory["source_files"]

    manifest = {
        "version": metadata["version"],
        "upstream": inventory["upstream"],
        "generator": inventory["generator"],
        "coverage": {
            "source_files": len(source_files),
            "included": len(source_files) - len(excluded),
            "excluded": len(excluded),
        },
        "source_inventory_sha256": hashlib.sha256(inventory_bytes).hexdigest(),
        "source": {
            "repository": "https://github.com/zbalkan/wazuh-rule-tests",
            "commit": args.commit,
        },
        "generated_at": build_timestamp(),
    }

    version = metadata["version"]
    args.output_dir.mkdir(parents=True, exist_ok=True)
    target = args.output_dir / f"wazuh-rule-tests-{version}.zip"
    manifest_path = args.output_dir / "manifest.json"
    manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    manifest_path.write_bytes(manifest_bytes)

    members = [ROOT / "LICENSE", ROOT / "README.md", INVENTORY]
    members.extend(
        sorted(
            path
            for path in (ROOT / "tests").rglob("*")
            if path.is_file()
            and "__pycache__" not in path.parts
            and path.suffix != ".pyc"
        )
    )

    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        write_bytes(archive, "manifest.json", manifest_bytes)
        for path in members:
            write_bytes(archive, path.relative_to(ROOT).as_posix(), path.read_bytes())

    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    checksum = target.with_suffix(target.suffix + ".sha256")
    checksum.write_text(f"{digest}  {target.name}\n", encoding="ascii")

    print(manifest_path)
    print(target)
    print(checksum)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
