# wazuh-rule-tests

`wazuh-rule-tests` is the versioned pytest regression corpus for built-in Wazuh rules and decoders.

The test files are generated with [wazuh-testgen](https://github.com/zbalkan/wazuh-testgen) and then reviewed and corrected manually where generated expectations conflict with actual Wazuh behavior.

The corpus is content, not a Python package. Tests use the public [wazuhtester](https://github.com/zbalkan/wazuhtester) API and require a running Wazuh manager with a reachable `wazuh-logtest` Unix socket.

## Source provenance

The test content was generated from the Wazuh `4.14.10` ruleset-testing snapshot:

```text
repository: https://github.com/wazuh/wazuh
ref:        4.14.10
commit:     eb4901c2d35f35aaa298463798b74704d569e4a6
path:       ruleset/testing/tests
```

Generation uses `wazuh-testgen` at:

```text
b2c38d0c41b9e3792bab2eed61f1ec130fe8beb1
```

The pinned source inventory is stored in `source/wazuh-4.14.10.json`.

It contains 107 upstream INI files:

```text
107 upstream INIs
 = 95 generated rule-test modules
 + 12 documented exclusions
```

The exclusions are intentional:

- ten `test_*.ini` files exercise regex, static-filter, or other ruleset-engine primitives rather than rule regression behavior;
- `unbound.ini` has all test conditions commented out upstream;
- `win_application.ini` has all test conditions commented out upstream.

`tools/validate_corpus.py` verifies this partition and fails if an included upstream INI has no generated pytest module, if a generated module has no source INI, or if its provenance marker is missing. The same source inventory also records the verified ruleset equivalence between Wazuh 4.14.8, 4.14.9, and 4.14.10 across `ruleset/rules`, `ruleset/decoders`, and `ruleset/testing/tests`: 395 files with no differences at the recorded commits.

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

## Compatibility

Compatibility is declared in `corpus.json`.

The current corpus revision is:

```text
4.14.8-r2
```

and is deliberately restricted to:

```text
Wazuh == 4.14.8
```

The generated content remains provenance-linked to the newer Wazuh `4.14.10` source snapshot. This is intentional: the recorded 4.14.8, 4.14.9, and 4.14.10 branch heads have identical rule, decoder, and ruleset-test content across all 395 relevant files. Wazuh 4.14.8 is therefore used as the first runtime qualification target because it is the earliest package target for which this exact corpus content is known to be applicable.

The compatibility range remains exact until live qualification justifies broadening it.

Corpus versions use:

```text
<Wazuh version>-r<corpus revision>
```

For example:

```text
4.14.8-r1
4.14.8-r2
4.15.0-r1
```

The revision increments when tests or corpus metadata change without changing the Wazuh qualification version.

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
- the exact Wazuh compatibility requirement and qualification target;
- the exact Wazuh upstream ref and commit;
- the exact `wazuh-testgen` commit;
- source/included/excluded counts;
- a SHA-256 digest of the source inventory;
- the exact `wazuh-rule-tests` content commit used to build the artifact.

Release tags must match the `corpus_version` in `corpus.json`. The release workflow installs the declared Wazuh qualification target, executes the exact extracted release ZIP against `wazuh-logtest`, and only then creates the GitHub release.

The first corpus release is gated on the availability of the Wazuh 4.14.8 Manager package and a successful live execution of the exact extracted release artifact against that package.

Consumers such as `wazuh-devenv` should use the release manifest as the compatibility contract rather than inferring compatibility from the archive filename.

## Ownership boundary

This repository owns expected Wazuh rule and decoder behavior. Environment preparation belongs to `wazuh-devenv`, logtest protocol handling belongs to `wazuhtester`, and test generation belongs to `wazuh-testgen`.

## License

GNU General Public License version 2 only. See [LICENSE](LICENSE).
