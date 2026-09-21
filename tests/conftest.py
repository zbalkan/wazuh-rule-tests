from __future__ import annotations

import os
import shutil
import stat
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest


_SUPPORT_DIRECTORY = Path(__file__).with_name("_wazuh_test_support")
_ENABLE_VARIABLE = "WAZUH_TESTGEN_UPSTREAM_HARNESS"


def _harness_enabled(request: pytest.FixtureRequest) -> bool:
    environment_enabled = os.environ.get(_ENABLE_VARIABLE, "").lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    return environment_enabled or bool(
        request.config.getoption("--wazuh-require-logtest", default=False)
    )


def _restore_file(path: Path, content: bytes, metadata: os.stat_result) -> None:
    path.write_bytes(content)
    os.chmod(path, stat.S_IMODE(metadata.st_mode))
    try:
        os.chown(path, metadata.st_uid, metadata.st_gid)
    except PermissionError:
        pass
    os.utime(
        path,
        ns=(metadata.st_atime_ns, metadata.st_mtime_ns),
    )


@pytest.fixture(scope="session", autouse=True)
def _wazuh_upstream_regression_environment(
    request: pytest.FixtureRequest,
):
    if not _harness_enabled(request):
        yield
        return

    wazuh_home = Path(os.environ.get("WAZUH_HOME", "/var/ossec"))
    base_rules = wazuh_home / "ruleset/rules/0575-win-base_rules.xml"
    rules_directory = wazuh_home / "etc/rules"
    decoders_directory = wazuh_home / "etc/decoders"

    if not base_rules.is_file():
        raise RuntimeError(
            f"Wazuh base rules not found at {base_rules}. "
            "Set WAZUH_HOME to the manager installation."
        )
    support_files = sorted(_SUPPORT_DIRECTORY.glob("*.xml"))
    if support_files and (
        not rules_directory.is_dir() or not decoders_directory.is_dir()
    ):
        raise RuntimeError(
            f"Wazuh custom rules/decoders directories not found under {wazuh_home}."
        )

    base_content = base_rules.read_bytes()
    base_metadata = base_rules.stat()
    installed: list[Path] = []
    replaced: dict[Path, tuple[bytes, os.stat_result]] = {}

    try:
        tree = ET.parse(base_rules)
        base_rule = tree.find('.//rule[@id="60000"]')
        if base_rule is None:
            raise RuntimeError(
                "Wazuh base rule 60000 was not found in "
                f"{base_rules}."
            )

        for tag in ("decoded_as", "category"):
            element = base_rule.find(tag)
            if element is not None:
                base_rule.remove(element)

        decoded_as = ET.SubElement(base_rule, "decoded_as")
        decoded_as.text = "json"
        tree.write(base_rules, encoding="utf-8")

        for source in support_files:
            target_directory = (
                decoders_directory
                if source.name.endswith("_decoders.xml")
                or source.name == "test_decoders.xml"
                else rules_directory
            )
            target = target_directory / source.name
            if target.exists():
                replaced[target] = (target.read_bytes(), target.stat())
            shutil.copy2(source, target)
            installed.append(target)

        yield
    finally:
        _restore_file(base_rules, base_content, base_metadata)
        for target in reversed(installed):
            backup = replaced.get(target)
            if backup is None:
                target.unlink(missing_ok=True)
            else:
                content, metadata = backup
                _restore_file(target, content, metadata)
