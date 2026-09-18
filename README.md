# wazuh-rule-tests

`wazuh-rule-tests` is the versioned pytest regression corpus for built-in Wazuh rules and decoders.

The test files are generated with [wazuh-testgen](https://github.com/zbalkan/wazuh-testgen) and then reviewed and corrected manually where generated expectations conflict with actual Wazuh behavior.

The corpus is content, not a Python package. Tests use the public [wazuhtester](https://github.com/zbalkan/wazuhtester) API and require a running Wazuh manager with a reachable `wazuh-logtest` Unix socket.

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

Source compatibility is declared in `corpus.json`. The first corpus series targets Wazuh 4.14, with Wazuh 4.14.7 as its release qualification target. A published release therefore implies that its live 4.14.7 qualification gate passed.

Released archives contain a generated `manifest.json` with immutable source provenance in addition to the static compatibility metadata.

Corpus versions use:

```text
<Wazuh series>-r<corpus revision>
```

For example:

```text
4.14-r1
4.14-r2
4.15-r1
```

The revision increments when tests or corpus metadata change without changing the target Wazuh series.

## Releases

A release contains:

```text
manifest.json
LICENSE
README.md
tests/
```

plus a SHA-256 checksum for the ZIP archive.

Release tags must match the `corpus_version` in `corpus.json`. The release workflow installs the released `wazuhtester` dependency, provisions the declared Wazuh version, executes the full corpus against the live `wazuh-logtest` daemon, and only then creates the GitHub release.

Consumers such as `wazuh-devenv` should use the release manifest as the compatibility contract rather than inferring compatibility from the archive filename.

## Ownership boundary

This repository owns expected Wazuh rule and decoder behavior. Environment preparation belongs to `wazuh-devenv`, logtest protocol handling belongs to `wazuhtester`, and test generation belongs to `wazuh-testgen`.

## License

GNU General Public License version 2 only. See [LICENSE](LICENSE).
