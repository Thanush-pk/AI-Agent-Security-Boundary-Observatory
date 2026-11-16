# Threat Model

What the Observatory tests, what it assumes, and what it deliberately does **not** cover.

## The scenario being modelled

An AI agent runs code inside a sandbox. The agent may be buggy, misled by a malicious
instruction (prompt injection), or simply compromised. The question this tool answers:

> If code inside the sandbox *tries* to cross a boundary, does the sandbox stop it?

## Attacker model

- Runs code **inside** the sandbox as an ordinary, unprivileged user.
- Can read and write whatever the sandbox allows, and can attempt any system call.
- Wants to: modify the host system, steal credentials, reach the network, or gain more privileges.

## What the 9 scenarios simulate

| ID | Attack simulated | PASS means | Known limits |
| :-- | :-- | :-- | :-- |
| `fs-001` | Write to the root filesystem (tamper with system files) | The write is refused | Tests one path (`/`); other writable mounts are not checked |
| `fs-002` | Drop a script in scratch space and execute it | Execution from `/tmp` is refused | Models Docker's `noexec` mount; other runtimes may restrict execution differently |
| `fs-003` | Read `/etc/shadow` (credential file) | Read is refused | One file only |
| `net-001` | Open an outbound TCP connection to a public IP | Connection is blocked | One destination and port |
| `net-002` | Resolve an external domain name | Lookup fails | Runtimes that answer DNS themselves (e.g. OpenShell) can only be judged `INCONCLUSIVE` |
| `net-003` | Reach the cloud metadata address `169.254.169.254` | Connection is blocked | Tests one address, not every metadata route |
| `proc-001` | Check whether the process runs as root | Runs as a non-root user | Checks identity, not capabilities |
| `proc-002` | Call `setuid(0)` to become root | Escalation is refused | One escalation method |
| `proc-003` | Create a raw network socket | Creation is refused (any refusal errno) | Does not test other privileged socket types |

## How a verdict is decided

- **PASS**: the probe reports the boundary held and the evidence agrees.
- **FAIL**: the probe reports it crossed the boundary.
- **INCONCLUSIVE**: the probe could not tell (timeout, crash, unexpected error, or a runtime
  behaviour the test cannot judge). This is a deliberate answer, not a failure of the tool.

Each verdict is backed by evidence records (probe observation, runtime log, system errors),
so a result can be audited rather than trusted.

## Out of scope

- Kernel or hypervisor vulnerabilities and container-escape exploits.
- Side channels, resource exhaustion (CPU, memory, process limits), IPC, and GPU isolation.
- Whether the *agent* behaves well. This tool tests the walls, not the occupant.
- Host configuration (for example, host firewall rules) beyond what the sandbox exposes.

## Limits of the conclusions

- Nine checks can show that a boundary **failed**. They cannot prove a sandbox is secure.
- Probes encode expectations from one runtime's behaviour. When a runtime enforces a rule
  differently, the probe may need adjusting. This happened during development: a raw-socket
  probe reported a false `FAIL` because it only recognised Docker's error code.
- Comparing runtimes is only fair if their configuration is comparable. Docker here is hardened
  by this project; OpenShell runs with its default policy.

## Responsible use

The probes are harmless, but they simulate attacks. Only run them against sandboxes and
systems you own or are authorised to test.
