# wazuh-rule-tests

`wazuh-rule-tests` is the pytest regression corpus for built-in Wazuh rules and decoders.

The test files are generated with [wazuh-testgen](https://github.com/zbalkan/wazuh-testgen) and then reviewed and corrected manually where generated expectations conflict with actual Wazuh behavior.

The corpus is content, not a Python package. Tests use the public [wazuhtester](https://github.com/zbalkan/wazuhtester) API and require a running Wazuh manager with a reachable `wazuh-logtest` Unix socket.

## Source provenance

The source inventory is stored in `source/inventory.json`. It records the immutable upstream Wazuh commit and path used to generate the corpus, together with the `wazuh-testgen` commit.

Current upstream source:

```text
repository: https://github.com/wazuh/wazuh
commit:     eb4901c2d35f35aaa298463798b74704d569e4a6
path:       ruleset/testing/tests
```

Generation uses `wazuh-testgen` at:

```text
b2c38d0c41b9e3792bab2eed61f1ec130fe8beb1
```

The inventory contains 107 upstream INI files:

```text
107 upstream INIs
 = 95 generated rule-test modules
 + 12 documented exclusions
```

The exclusions are intentional:

- ten `test_*.ini` files exercise regex, static-filter, or other ruleset-engine primitives rather than rule regression behavior;
- `unbound.ini` has all test conditions commented out upstream;
- `win_application.ini` has all test conditions commented out upstream.

`tools/validate_corpus.py` verifies the inventory partition, generated-module coverage, provenance markers, and public API dependency boundary. It does not infer compatibility from Wazuh branches, refs, source versions, or equivalence tables.

## Development use

Install the prerelease development requirements:

```bash
python -m venv .venv
.venv/bin/pip install -r requirements-ci.txt
```

Static validation and collection do not require a Wazuh manager:

```bash
.venv/bin/python tools/validate_corpus.py
.venv/bin/python -m pytest --collect-only -q
```

To execute the corpus against a local manager:

```bash
.venv/bin/python -m pytest -v --wazuh-require-logtest
```

The account running pytest must be able to access the Wazuh logtest socket, normally:

```text
/var/ossec/queue/sockets/logtest
```

## Version

The current corpus version is:

```text
4.14.7
```

This is also the Wazuh version used to qualify the release. There is no separate compatibility expression, qualification target, schema version, source version, or corpus revision suffix.

Source provenance is independent of this version and is recorded by immutable commit SHA in `source/inventory.json`.

## Releases

A release contains:

```text
manifest.json
LICENSE
README.md
source/
tests/
```

plus a SHA-256 checksum for the ZIP archive.

The generated `manifest.json` records:

- the corpus version;
- the upstream Wazuh repository, commit, and source path;
- the exact `wazuh-testgen` commit;
- source/included/excluded counts;
- a SHA-256 digest of the source inventory;
- the exact `wazuh-rule-tests` commit used to build the artifact.

Release tags must match `version` in `corpus.json`. The release workflow installs that Wazuh version, executes the exact extracted release archive against `wazuh-logtest`, and only then creates the GitHub release.

Consumers such as `wazuh-devenv` should use the release manifest rather than inferring provenance from filenames.

## Ownership boundary

This repository owns expected Wazuh rule and decoder behavior. Environment preparation belongs to `wazuh-devenv`, logtest protocol handling belongs to `wazuhtester`, and test generation belongs to `wazuh-testgen`.

## License

GNU General Public License version 2 only. See [LICENSE](LICENSE).
