# Agent Boundary Observatory — Test Results

**Report date:** 15 November 2026  
**Project:** Agent Boundary Observatory  
**Test environment:** Python 3.13.15, pytest 9.1.1, Docker Desktop 29.6.2  
**Runtime under test:** Docker-based restricted container runtime

---

## 1. Executive summary

The current test run demonstrates that the Docker runtime restrictions are being exercised and that the assessment pipeline can distinguish successful boundary enforcement from deliberate boundary violations.

| Measure | Result |
|---|---:|
| Automated test suite | **22 passed** |
| Security scenarios in the hardened-runtime assessment | **9** |
| Hardened-runtime scenario results | **9 PASS** |
| Timeline evidence events reported | **19** |
| Controlled negative-test violations detected | **2 FAIL** |
| Regression comparison alerts | **2 security regressions** |

The controlled negative tests are particularly important: the evaluator did not simply report success for every run. When the runtime was deliberately made permissive, it detected a filesystem write and execution with UID 0, classified both as failures, and the comparison command raised security-regression alerts.

## 2. Automated test suite

The reported full test-suite result was:

```text
22 passed
```

The suite covers the implemented evidence models, evaluator, Docker runtime, assessment engine, security scenarios, report export/loading, and forensic timeline/regression functionality.

> This count reflects the test output shared for this report. It is not a fresh test execution.

## 3. Hardened Docker runtime assessment

The restricted runtime was configured with controls including:

- Read-only container root filesystem
- Network disabled
- Unprivileged user (`65534:65534`)
- All Linux capabilities dropped
- `no-new-privileges`
- Restricted temporary filesystem (`noexec,nosuid`)
- Memory, CPU, and process limits
- No host filesystem mounts

The nine reported scenarios produced the following results:

| Scenario | Boundary tested | Observed result | Verdict |
|---|---|---|---|
| `fs-001` | Write to container root filesystem | Write blocked; `EROFS` observed | **PASS** |
| `fs-002` | Execute a script from `/tmp` | Execution blocked; `EACCES` observed | **PASS** |
| `fs-003` | Read `/etc/shadow` | Access denied; `EACCES` observed | **PASS** |
| `net-001` | Outbound network access | Network unreachable; `ENETUNREACH` observed | **PASS** |
| `net-002` | DNS/network access | DNS access blocked | **PASS** |
| `net-003` | Cloud metadata endpoint access | Network unreachable; `ENETUNREACH` observed | **PASS** |
| `proc-001` | Process user identity | Process ran as UID `65534`, GID `65534` | **PASS** |
| `proc-002` | Privilege escalation attempt | Operation denied; `EPERM` observed | **PASS** |
| `proc-003` | Raw socket access | Operation denied; `EPERM` observed | **PASS** |

The forensic timeline output contained **19 evidence events** across the nine scenarios, including test observations and runtime-log records.

## 4. Controlled negative tests

A permissive test runtime was introduced intentionally to verify that the evaluator detects a boundary breach. Its configuration relaxed key restrictions:

- `read_only=False`
- `network_disabled=False`
- `user="0:0"`

Two negative tests demonstrated detection:

### 4.1 Filesystem write succeeds when it should be blocked

| Field | Result |
|---|---|
| Scenario | `fs-001` |
| Action | Write `/test_boundary.txt` |
| Observation | File write succeeded |
| Runtime exit code | `0` |
| Verdict | **FAIL** |

Reported reason:

```text
Security boundary violated: File successfully written to root filesystem: /test_boundary.txt
```

The evidence recorded `boundary_held=false` and the observed behavior as success.

### 4.2 Process runs as root

| Field | Result |
|---|---|
| Scenario | `proc-001` |
| Action | Inspect process UID/GID |
| Observation | UID `0`, GID `0` |
| Runtime exit code | `0` |
| Verdict | **FAIL** |

Reported reason:

```text
Security boundary violated: Container running with root privileges (UID=0)
```

The evidence recorded `boundary_held=false`, UID `0`, and GID `0`.

## 5. Regression comparison

The baseline hardened-runtime report was compared with the permissive-runtime report.

```text
[REGRESSION] fs-001 (PASS -> FAIL): SECURITY REGRESSION
[REGRESSION] proc-001 (PASS -> FAIL): SECURITY REGRESSION

Security Regressions: 2
Degradations: 0
Improvements: 0

ALERT: Security regression detected!
```

The comparison command returned a non-zero exit code (`1`), making the result suitable for use as a CI quality gate: a detected security regression can fail the pipeline.

## 6. What these results establish

Based on the shared outputs, the current implementation demonstrates that it can:

1. Execute security scenarios inside a Docker-based restricted runtime.
2. capture test observations separately from runtime logs.
3. Produce deterministic `PASS`, `FAIL`, and `INCONCLUSIVE` verdicts according to the evaluator's evidence rules.
4. Export and reload assessment reports in JSON.
5. Reconstruct a chronological evidence timeline.
6. Compare two assessment reports and identify `PASS → FAIL` security regressions.
7. Return a non-zero process exit code when a security regression is detected.

## 7. Scope and limitations

These results apply to the tested Docker configuration and the scenarios that were executed. They should not be interpreted as proof that the host, Docker daemon, every network path, or every cloud environment is secure.

In particular:

- A container's UID 0 is not the same as host-level root access. The negative test demonstrates that the configured container process ran as root, not that it escaped the container.
- Network-disabled container tests demonstrate the behavior of that configured network environment. They do not independently prove that every possible route to every metadata service is blocked in all deployments.
- The DNS and metadata checks are limited to the specific test methods and endpoints used by the scenarios.
- The report records the results shared in the conversation; raw JSON assessment reports and complete pytest output were not supplied as attachments for independent verification.

## 8. Recommended next milestone

The next meaningful milestone is to implement and validate an **OpenShell runtime adapter** using the same assessment-engine contract. Run equivalent scenarios under OpenShell, capture runtime-native evidence where available, and compare the results with the Docker baseline.

The evaluator should not assume that OpenShell has Docker's enforcement behavior. Each runtime's policy and evidence sources should be validated independently.

---

**Status:** Docker assessment pipeline has a working reported test baseline, controlled negative-test coverage, report export, forensic timeline, and regression detection. An OpenShell adapter has since been added and compared against this Docker baseline; see the Findings section of the README.
