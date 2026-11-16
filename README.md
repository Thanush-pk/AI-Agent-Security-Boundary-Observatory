# Agent Boundary Observatory

[![CI](https://github.com/Thanush-pk/AI-Agent-Security-Boundary-Observatory/actions/workflows/ci.yml/badge.svg)](https://github.com/Thanush-pk/AI-Agent-Security-Boundary-Observatory/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/Python-3.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](LICENSE)

Tests whether AI-agent sandboxes actually contain the code running inside them.

The Observatory runs 9 harmless escape attempts (filesystem, network, privilege) inside disposable sandboxes, records evidence for each, and returns a `PASS`, `FAIL` or `INCONCLUSIVE` verdict. It supports **Docker** and **NVIDIA OpenShell**, and can compare the two.

## Findings: Docker vs. NVIDIA OpenShell

The same 9 scenarios were run against both runtimes on 2026-11-16.

- **Machine:** Ubuntu 26.04 (aarch64), ASUS GX10 with NVIDIA GB10
- **Versions:** Docker Engine 29.6.2, OpenShell 0.1.8
- **Same for both:** image `python:3.12-slim`, 0.5 CPU, 128 MB memory
- **Docker** uses the hardened configuration in `DockerRuntime` (all capabilities dropped, read-only root, `noexec` tmpfs, no network, non-root user).
- **OpenShell** uses its **default** policy. No custom policy was applied.

| Scenario | Docker | OpenShell | What happened on OpenShell |
| :-- | :--: | :--: | :-- |
| `fs-001` Read-only root | PASS | PASS | Write refused (`EACCES`) |
| `fs-002` No exec from `/tmp` | PASS | **FAIL** | A script ran from `/tmp` |
| `fs-003` Credential file read | PASS | PASS | `/etc/shadow` read refused |
| `net-001` Outbound TCP | PASS | PASS | Refused with a permission error |
| `net-002` DNS resolution | PASS | **INCONCLUSIVE** | Lookup succeeds with a placeholder address |
| `net-003` Cloud metadata (IMDS) | PASS | PASS | Refused with a permission error |
| `proc-001` Non-root user | PASS | PASS | UID 1000 (Docker: 65534). Both unprivileged |
| `proc-002` `setuid(0)` | PASS | PASS | `EPERM` |
| `proc-003` Raw socket | PASS | PASS | Refused with `EPROTONOSUPPORT` |

**Totals:** Docker 9 PASS. OpenShell 7 PASS, 1 FAIL, 1 INCONCLUSIVE.
Raw data: [`docker_report.json`](docs/sample-reports/docker_report.json), [`openshell_report.json`](docs/sample-reports/openshell_report.json). Rendered page: [`docs/index.html`](docs/index.html).

**What the results mean**

- **`fs-002` is a real difference in defaults.** OpenShell's default policy allowed executing a script from `/tmp`; the Docker setup blocks it with a `noexec` mount. OpenShell restricts files by a different mechanism, so this is a difference to be aware of, not necessarily a vulnerability. Whether a custom policy closes it has not been tested yet.
- **`net-002` cannot be judged by this probe.** `google.com` and a name that cannot exist (`no-such-host-xyz.example`) both resolved to `198.18.0.2`, a reserved benchmarking address, while direct connections (`net-001`, `net-003`) were refused. This suggests OpenShell answers DNS itself and enforces its rules at connection time. That is an inference from these observations, not something confirmed in OpenShell's documentation. The probe reports `INCONCLUSIVE` instead of a false `FAIL`.
- **`proc-003` first showed a false `FAIL`.** OpenShell did refuse the raw socket, with a different error code than Docker's `EPERM`, and the probe only recognised `EPERM`. The probe now accepts any "denied" code and treats unrelated errors as `INCONCLUSIVE`.

**Caveats:** this compares a hardened Docker setup with OpenShell defaults, so it is not a ranking of the two. It is one machine, one run and nine checks. Failures are informative, but passing does not prove a sandbox is secure. See the [threat model](docs/threat-model.md).

## Quickstart

Requires Python 3.11+ and Docker. For `--runtime openshell`, also the [OpenShell](https://github.com/NVIDIA/OpenShell) CLI with its gateway running (`openshell status` should succeed).

```bash
git clone https://github.com/Thanush-pk/AI-Agent-Security-Boundary-Observatory.git
cd AI-Agent-Security-Boundary-Observatory
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

observatory scenarios                                   # list the 9 scenarios
observatory run -o docker_report.json                   # assess Docker (default)
observatory run -r openshell -o openshell_report.json   # assess OpenShell
observatory compare docker_report.json openshell_report.json
observatory html docker_report.json openshell_report.json -o report.html
observatory timeline docker_report.json                 # evidence in time order
```

`run` exits with code 2 if any scenario fails, and `compare` exits with code 1 if a boundary that held before no longer does, so both can gate a CI pipeline. Across two runtimes, read `compare`'s "regression" as "differs from the baseline".

## How it works

1. **Scenario:** a small probe tries one escape (for example, writing to the root filesystem) and prints what it observed.
2. **Runtime adapter:** runs the probe in a disposable sandbox (`DockerRuntime`, `OpenShellRuntime`) and returns its output and exit code.
3. **Verdict:** the evaluator combines the probe's observation, the runtime log and any system errors. `INCONCLUSIVE` means the evidence could not verify the boundary (timeout, crash, unexpected output).
4. **Report:** results are saved as portable JSON, which feeds the timeline, comparison and HTML views.

The 9 scenarios, what each simulates, and their limits are in [`docs/threat-model.md`](docs/threat-model.md).

## Adding a runtime

Implement the `Runtime` protocol from `src/observatory/runtime/base.py` (`check_available()` and `run_python()`), then register the class in `RUNTIMES` in `src/observatory/cli.py`. `openshell_runtime.py` is a compact example.

## Development

```bash
pytest -v        # unit tests, plus integration tests that need Docker
ruff check .
```


## Docs and license

[Threat model](docs/threat-model.md) · [Docker baseline test results](AGENT_BOUNDARY_OBSERVATORY_TEST_RESULTS.md) · [Apache 2.0](LICENSE)

Only run these probes against sandboxes and systems you own or are authorised to test.
