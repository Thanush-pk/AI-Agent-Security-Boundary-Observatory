# Agent Boundary Observatory

**Evidence-based security assessments and boundary verification for AI agent runtimes.**

[![Python](https://img.shields.io/badge/Python-3.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://python.org)
[![Docker](https://img.shields.io/badge/Runtime-Docker%20Sandbox-2496ED.svg)](https://www.docker.com/)
[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](LICENSE)
[![CI](https://github.com/Thanush-pk/AI-Agent-Security-Boundary-Observatory/actions/workflows/ci.yml/badge.svg)](https://github.com/Thanush-pk/AI-Agent-Security-Boundary-Observatory/actions/workflows/ci.yml)

---

## What is Agent Boundary Observatory?

The **Agent Boundary Observatory** is an open-source security assessment and forensics platform built to evaluate whether AI agents and their execution environments strictly respect sandbox boundaries, isolation controls, and operating system security policies.

As autonomous AI agents are granted access to execute code, manipulate tools, and interact with operating systems, relying solely on model prompt alignment is insufficient. Security requires verifiable, defense-in-depth enforcement at the runtime level. The Observatory executes controlled security scenarios inside disposable sandbox containers and microVMs, intercepts runtime events and OS error states, collects verifiable forensic evidence, and produces both machine-readable JSON artifacts (`report.json`) and audit-ready executive summaries ([AGENT_BOUNDARY_OBSERVATORY_TEST_RESULTS.md](AGENT_BOUNDARY_OBSERVATORY_TEST_RESULTS.md)).

---

## What Does it Demonstrate?

1. **Active Boundary Enforcement Testing**:
   Executes realistic threat vectors (e.g., unauthorized root writes, execution from scratch directories, outbound TCP/DNS egress, cloud metadata harvesting, and setuid privilege escalation) to verify whether sandbox boundaries actually prevent unauthorized operations.

2. **Evidence-Driven Verdicts (`PASS` | `FAIL` | `INCONCLUSIVE`)**:
   Rather than relying on surface-level exit codes alone, the platform correlates multiple independent evidence sources:
   - **Test Observations**: High-fidelity probe assertions, OS errno codes, and post-condition checks.
   - **Runtime Logs**: Stdout/stderr streams, container exit statuses, and resource caps.
   - **System Errors**: Timeouts and container faults that trigger an explicit `INCONCLUSIVE` verdict when evidence cannot verify the boundary.

3. **Incident Forensics & Timeline Reconstruction**:
   Aggregates granular, timestamped evidence records into a chronological incident timeline, allowing security engineers to trace exactly how an execution progressed and identify the precise point of failure.

4. **Security Regression Detection**:
   Compares assessment runs against baselines (e.g., across agent versions or sandbox configuration changes) to instantly flag security boundary regressions (`PASS` $\to$ `FAIL`) or degradations in CI/CD pipelines.

---

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
Raw reports: [`docker_report.json`](docs/sample-reports/docker_report.json), [`openshell_report.json`](docs/sample-reports/openshell_report.json).

### What the results mean

- **`fs-002` is a real difference in defaults.** OpenShell's default policy allowed executing a script from `/tmp`, while the Docker setup blocks it with a `noexec` mount. OpenShell restricts files with a different mechanism, so this is a difference to be aware of, not necessarily a vulnerability. A custom policy might close it, which has not been tested yet.
- **`net-002` cannot be judged by this probe.** `google.com` and a name that cannot exist (`no-such-host-xyz.example`) both resolved to `198.18.0.2`, a reserved benchmarking address. Meanwhile direct connections (`net-001`, `net-003`) were refused. This suggests OpenShell answers DNS itself and enforces its rules when a connection is attempted. That is an inference from these observations, not something confirmed in OpenShell's documentation. The probe reports `INCONCLUSIVE` for this case instead of a false `FAIL`.
- **`proc-003` first showed a false `FAIL`.** OpenShell did refuse the raw socket, with a different error code than Docker's `EPERM`, and the probe only recognised `EPERM`. The probe now accepts any refusal code that means "denied" and treats unrelated errors as `INCONCLUSIVE`.

### Caveats

- This compares a **hardened Docker setup** with **OpenShell defaults**. It is not a ranking of the two technologies.
- One machine, one run, nine checks. Failures are informative, but passing does not prove a sandbox is secure. See the [threat model](docs/threat-model.md) for scope and limits.

To reproduce:

```bash
observatory run --runtime docker -o docker_report.json
observatory run --runtime openshell -o openshell_report.json
observatory compare docker_report.json openshell_report.json
```

> `compare` labels differences as `REGRESSION`. That wording fits the same runtime changing over time. Across two runtimes, read it as "diverges from the baseline".

---

## Why is This Useful?

- **AI Agent Developers & Frameworks**: Benchmark and audit execution sandboxes before deploying autonomous agents with access to real tools or APIs.
- **Enterprise Security Teams**: Validate that multi-tenant or third-party agent workloads are truly isolated and cannot exfiltrate data, tamper with host systems, or pivot to internal networks.
- **Red Teams & Security Researchers**: Systematically evaluate container and microVM isolation layers (e.g., Docker, NVIDIA OpenShell, gVisor, Firecracker) against agent exploitation techniques.
- **CI/CD Quality Gates**: Automatically prevent deployments if a configuration change weakens filesystem, network, or capability isolation.

---

## Architecture Overview

```
                                      +------------------------+
                                      |   Observatory CLI /    |
                                      |   Automated CI Gate    |
                                      +-----------+------------+
                                                  |
                                                  v
                                      +------------------------+
                                      |   Assessment Engine    |
                                      +-----------+------------+
                                                  |
                         +------------------------+------------------------+
                         |                                                 |
                         v                                                 v
           +---------------------------+                     +---------------------------+
           |     Security Scenario     |                     |     Runtime Adapter       |
           |   (Threat + Probe Code)   |                     |  (Docker / OpenShell)     |
           +-------------+-------------+                     +-------------+-------------+
                         |                                                 |
                         +------------------------+------------------------+
                                                  |
                                                  v
                                      +------------------------+
                                      |   Disposable Sandbox   |
                                      |       Execution        |
                                      +-----------+------------+
                                                  |
                                                  v
                                      +------------------------+
                                      |   Verdict Evaluator    |
                                      | (PASS/FAIL/INCONCLUSIVE|
                                      +-----------+------------+
                                                  |
                         +------------------------+------------------------+
                         |                                                 |
                         v                                                 v
           +---------------------------+                     +---------------------------+
           |   Assessment Reports      |                     |    Forensics & Timeline   |
           | (Portable JSON Artifacts) |                     |  & Regression Detection   |
           +---------------------------+                     +---------------------------+
```

---

## Implemented Security Scenarios

The Observatory includes a baseline suite of 9 controlled boundary scenarios across three core domains:

### 1. Filesystem Boundaries
| ID | Scenario | Threat Tested | Expected Boundary Behavior |
| :--- | :--- | :--- | :--- |
| `fs-001` | **Read-Only Root Filesystem** | Modifying system binaries or root configuration | Writes outside `/tmp` must fail with `EROFS` / `EACCES`. |
| `fs-002` | **Tmpfs No-Execution** | Dropping and executing staged binaries in scratch space | File is writable in `/tmp`, but execution must fail with `EACCES` due to `noexec`. |
| `fs-003` | **Sensitive Credential Protection** | Harvesting password hashes from `/etc/shadow` | Read access must fail with `EACCES` for unprivileged processes. |

### 2. Network Isolation Boundaries
| ID | Scenario | Threat Tested | Expected Boundary Behavior |
| :--- | :--- | :--- | :--- |
| `net-001` | **Direct Outbound IP Egress** | Exfiltrating data or establishing outbound C2 socket | TCP connection to public IP must fail with `ENETUNREACH`. |
| `net-002` | **External DNS Name Resolution** | Domain reconnaissance or DNS tunneling | Lookup for external domain names must fail with `gaierror`. |
| `net-003` | **Cloud Metadata Isolation (IMDS)** | Stealing cloud IAM credentials via `169.254.169.254` | Link-local connections must be rejected with `ENETUNREACH`. |

### 3. Process & Privilege Boundaries
| ID | Scenario | Threat Tested | Expected Boundary Behavior |
| :--- | :--- | :--- | :--- |
| `proc-001` | **Unprivileged Identity Enforcement** | Running with administrative or root UID 0 | Process must execute as non-root user (`nobody:nogroup`, UID 65534). |
| `proc-002` | **Privilege Escalation Prevention** | Invoking `setuid(0)` syscall to elevate to root | Escalation must be rejected with `EPERM` via `no-new-privileges` and capability drops. |
| `proc-003` | **Raw Socket Creation Denial** | Packet injection, sniffing, or ARP poisoning | Creating raw sockets (`SOCK_RAW`) must fail with `EPERM` via dropped `CAP_NET_RAW`. |

---

## Getting Started

### Prerequisites
- Python 3.11+
- Docker Desktop or Docker Engine running locally
- Optional, for `--runtime openshell`: the [NVIDIA OpenShell](https://github.com/NVIDIA/OpenShell) CLI with its gateway running (`openshell status` should succeed)

Developed and tested on Ubuntu 26.04 (aarch64) with Docker Engine 29.

### Installation

```bash
# Clone the repository
git clone https://github.com/Thanush-pk/AI-Agent-Security-Boundary-Observatory.git
cd AI-Agent-Security-Boundary-Observatory

# Create and activate a virtual environment
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate

# Install dependencies in editable mode
pip install -e ".[dev]"
```

---

## CLI Usage

### 1. View Available Scenarios
```bash
observatory scenarios
```

### 2. Run a Single Scenario
```bash
# By positional name or flag
observatory run fs-002
observatory run --scenario net-001
```

### 3. Run the Full Security Assessment & Export JSON
```bash
observatory run --output report.json

# Choose the runtime to assess: docker (default) or openshell
observatory run --runtime openshell
```

Output:
```text
Running assessment with 9 scenario(s) against docker...

[PASS] fs-001: Read-Only Root Filesystem Boundary
       Reason: Write access prevented by filesystem boundary (OSError: [Errno 30] Read-only file system: '/test_boundary.txt')
       Evidence records: 2

[PASS] fs-002: Tmpfs No-Execution Boundary
       Reason: Script execution denied from /tmp by noexec mount (PermissionError: [Errno 13] Permission denied: '/tmp/test_exec.sh')
       Evidence records: 2

[PASS] fs-003: Sensitive Credential Store Read Protection
       Reason: Protected credential store read denied (PermissionError: [Errno 13] Permission denied: '/etc/shadow')
       Evidence records: 2

[PASS] net-001: Direct Outbound IP Egress Restriction
       Reason: Outbound network connection was blocked (OSError: [Errno 101] Network is unreachable)
       Evidence records: 2

[PASS] net-002: External DNS Name Resolution Restriction
       Reason: DNS resolution blocked by network sandbox (gaierror: [Errno -3] Temporary failure in name resolution)
       Evidence records: 2

[PASS] net-003: Cloud Instance Metadata Service (IMDS) Isolation
       Reason: Cloud metadata service access blocked (OSError: [Errno 101] Network is unreachable)
       Evidence records: 2

[PASS] proc-001: Unprivileged User Identity Enforcement
       Reason: Unprivileged identity enforced (UID=65534, GID=65534)
       Evidence records: 2

[PASS] proc-002: Privilege Escalation Prevention (setuid)
       Reason: Privilege escalation prevented (PermissionError: [Errno 1] Operation not permitted)
       Evidence records: 2

[PASS] proc-003: Raw Socket Creation Denial (CAP_NET_RAW)
       Reason: Raw socket denied by capability boundary (PermissionError: [Errno 1] Operation not permitted)
       Evidence records: 2

Assessment Summary:
  PASS: 9 | FAIL: 0 | INCONCLUSIVE: 0

Report saved to: report.json
```

### 4. Reconstruct Incident Timeline
```bash
observatory timeline report.json
```

### 5. Render a Shareable HTML Report
```bash
observatory html docker_report.json openshell_report.json -o report.html
```
Produces one self-contained page (no external files or scripts) with the runtimes side by side, a results table, and expandable per-scenario details. Pass a single report for a single-runtime page. The page for the sample results in this repo is [`docs/index.html`](docs/index.html).

### 6. Compare Assessment Runs (Detect Regressions)
```bash
observatory compare baseline_report.json current_report.json
```
If any scenario changed from `PASS` to `FAIL`, the command flags a `[REGRESSION]` and exits with code `1`, halting failing CI/CD builds.

---

## Running Tests

Run the full integration and unit test suite:

```bash
pytest -v
```

Check code formatting and linting:

```bash
ruff check .
```

---

## Technology Stack

- **Core Engine & CLI**: Python 3.11+, Typer, Pydantic v2
- **Runtime Virtualization**: Docker SDK for Python (isolated, disposable containers) and the NVIDIA OpenShell CLI (disposable sandboxes)
- **Forensics & Reports**: Chronological event ordering, JSON schema validation, regression diffing
- **Future Integrations**: FastAPI REST service and React / TypeScript visualization dashboard

---

## Roadmap

The OpenShell adapter and the first Docker vs. OpenShell comparison are done (see [Findings](#findings-docker-vs-nvidia-openshell)). Next come OpenShell-specific follow-ups, API persistence and a web dashboard.

### 1. OpenShell Follow-ups

[NVIDIA OpenShell](https://github.com/NVIDIA/OpenShell) is implemented as `OpenShellRuntime` (`src/observatory/runtime/openshell_runtime.py`), selected with `observatory run --runtime openshell`. Each probe runs in a disposable sandbox created through the `openshell` CLI.

- **Custom policy run:** apply an OpenShell `--policy` file that restricts execution from `/tmp`, and check whether `fs-002` changes from FAIL to PASS.
- **Stronger DNS scenario:** resolve a name and then try to connect to the answer, so the test works on runtimes that answer DNS themselves.
- **Runtime-native evidence:** capture OpenShell-specific isolation artifacts (GPU device exposure, driver boundaries, namespaces) as `EvidenceRecord` sources.

---

### 2. FastAPI REST API & Persistent Storage

- **REST API Endpoints (`src/observatory/api/`)**:
  - `POST /api/v1/assessments/run`: Trigger assessment suites asynchronously across Docker or OpenShell runtimes.
  - `GET /api/v1/assessments/{id}`: Fetch stored assessment results, verdict summaries, and raw JSON.
  - `GET /api/v1/assessments/{id}/timeline`: Retrieve the reconstructed forensic event timeline.
  - `POST /api/v1/assessments/compare`: Diff two assessment runs and detect regressions.
- **SQLite Persistence (`src/observatory/storage/`)**:
  - Persist assessment reports, historical trends, and timeline events to a local SQLite database using SQLModel / SQLAlchemy.

---

### 3. React & TypeScript Web Dashboard (`frontend/`)

- Interactive web dashboard for visualizing boundary enforcement:
  - **Verdict Summary Badges**: Real-time pass/fail matrix across filesystem, network, and process boundaries.
  - **Interactive Forensic Timeline**: Visual chronological timeline of probe assertions and container log events.
  - **Side-by-Side Diffing**: Visual comparison of baseline vs. current runs highlighting security regressions in red.

---

### 4. Extended Boundary Scenarios & Automated Markdown Reports

- **Extended Threat Scenarios**:
  - *IPC Isolation*: Probing shared memory (`/dev/shm`) and inter-process signals across containers.
  - *Resource Exhaustion*: Testing defenses against PID exhaustion (fork bombs) and out-of-memory crashes.
  - *Environment Leaks*: Detecting inadvertent leakage of host environment variables or sensitive credentials into agent execution space.
- **Automated Markdown Report Generation**:
  - Add an `observatory report --format markdown` CLI command to automatically generate executive audit reports (matching the structure of [AGENT_BOUNDARY_OBSERVATORY_TEST_RESULTS.md](AGENT_BOUNDARY_OBSERVATORY_TEST_RESULTS.md)) directly from any `report.json`.

---

## Roadmap Checklist

- [x] Runtime adapter protocol & disposable Docker sandbox
- [x] Evidence models and verdict evaluation (`PASS`, `FAIL`, `INCONCLUSIVE`)
- [x] 9 baseline controlled boundary scenarios (Filesystem, Network, Process)
- [x] Forensic timeline reconstruction & run comparison / regression detection
- [x] CLI commands (`run`, `scenarios`, `timeline`, `compare`)
- [x] Runtime selection via `--runtime` (registry-based: `docker`, `openshell`)
- [x] GitHub Actions CI (lint and tests on Python 3.11, 3.12 and 3.13)
- [x] [Threat model](docs/threat-model.md) documenting scope and limits
- [x] Executive test results documentation ([AGENT_BOUNDARY_OBSERVATORY_TEST_RESULTS.md](AGENT_BOUNDARY_OBSERVATORY_TEST_RESULTS.md))
- [x] NVIDIA OpenShell runtime adapter (`OpenShellRuntime`)
- [x] First differential benchmark (Docker vs. OpenShell, default policy)
- [ ] OpenShell custom-policy run and stronger DNS scenario
- [ ] FastAPI REST API and persistent storage (SQLite)
- [ ] React / TypeScript web observatory dashboard
- [ ] Extended scenario catalog (IPC boundaries, resource caps, environment leaks)
