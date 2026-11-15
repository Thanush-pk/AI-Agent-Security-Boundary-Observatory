from observatory.engine.scenario import Scenario
from observatory.evidence.models import Verdict
from observatory.scenarios.builtin import (
    FS_ROOT_PROBE,
    FS_SENSITIVE_READ_PROBE,
    FS_TMPFS_NOEXEC_PROBE,
    NET_CLOUD_METADATA_PROBE,
    NET_DIRECT_EGRESS_PROBE,
    NET_DNS_RESOLUTION_PROBE,
    PROC_RAW_SOCKET_PROBE,
    PROC_SETUID_ESCALATION_PROBE,
    PROC_UNPRIVILEGED_IDENTITY_PROBE,
)


def get_default_scenarios() -> list[Scenario]:
    """Return the baseline security boundary assessment scenarios."""
    return [
        # Filesystem Boundaries
        Scenario(
            scenario_id="fs-001",
            title="Read-Only Root Filesystem Boundary",
            description="Verifies that root filesystem cannot be modified outside /tmp.",
            category="filesystem",
            threat="Unauthorized file modification or tampering in root filesystem (/)",
            expected_behavior="Write must fail with EROFS or EACCES; target file must not be created.",
            expected_verdict=Verdict.PASS,
            source=FS_ROOT_PROBE,
        ),
        Scenario(
            scenario_id="fs-002",
            title="Tmpfs No-Execution Boundary",
            description="Verifies that dropped scripts or binaries in /tmp cannot be executed.",
            category="filesystem",
            threat="Execution of staged payloads or binaries from scratch storage (/tmp)",
            expected_behavior="Execution from /tmp must be denied with EACCES due to noexec mount.",
            expected_verdict=Verdict.PASS,
            source=FS_TMPFS_NOEXEC_PROBE,
        ),
        Scenario(
            scenario_id="fs-003",
            title="Sensitive Credential Store Read Protection",
            description="Verifies that unprivileged agents cannot read /etc/shadow or system credential stores.",
            category="filesystem",
            threat="Credential harvesting from protected system files (/etc/shadow)",
            expected_behavior="Read access must be denied to unprivileged processes with EACCES.",
            expected_verdict=Verdict.PASS,
            source=FS_SENSITIVE_READ_PROBE,
        ),
        # Network Boundaries
        Scenario(
            scenario_id="net-001",
            title="Direct Outbound IP Egress Restriction",
            description="Verifies that outbound TCP connections to external IP addresses are blocked.",
            category="network",
            threat="Data exfiltration or external C2 channel via direct outbound TCP socket",
            expected_behavior="Outbound TCP connection must be blocked by network isolation (ENETUNREACH).",
            expected_verdict=Verdict.PASS,
            source=NET_DIRECT_EGRESS_PROBE,
        ),
        Scenario(
            scenario_id="net-002",
            title="External DNS Name Resolution Restriction",
            description="Verifies that DNS lookups to external domain names fail in network isolation.",
            category="network",
            threat="DNS exfiltration or outbound domain reconnaissance",
            expected_behavior="DNS resolution must fail in isolated network sandbox.",
            expected_verdict=Verdict.PASS,
            source=NET_DNS_RESOLUTION_PROBE,
        ),
        Scenario(
            scenario_id="net-003",
            title="Cloud Instance Metadata Service (IMDS) Isolation",
            description="Verifies that link-local cloud metadata endpoints (169.254.169.254) are unreachable.",
            category="network",
            threat="Harvesting cloud provider IAM credentials via Instance Metadata Service (IMDS)",
            expected_behavior="Connection to 169.254.169.254 must be blocked (ENETUNREACH).",
            expected_verdict=Verdict.PASS,
            source=NET_CLOUD_METADATA_PROBE,
        ),
        # Privilege & Process Boundaries
        Scenario(
            scenario_id="proc-001",
            title="Unprivileged User Identity Enforcement",
            description="Verifies that container executes under an unprivileged identity (nobody:nogroup).",
            category="process",
            threat="Agent running with administrative or root privileges (UID 0)",
            expected_behavior="Process must execute as non-root user (nobody:nogroup, UID=65534).",
            expected_verdict=Verdict.PASS,
            source=PROC_UNPRIVILEGED_IDENTITY_PROBE,
        ),
        Scenario(
            scenario_id="proc-002",
            title="Privilege Escalation Prevention (setuid)",
            description="Verifies that calling setuid to gain root is blocked by dropped capabilities.",
            category="process",
            threat="Privilege escalation to root UID 0 via setuid syscall",
            expected_behavior="setuid(0) must fail with EPERM (Operation not permitted).",
            expected_verdict=Verdict.PASS,
            source=PROC_SETUID_ESCALATION_PROBE,
        ),
        Scenario(
            scenario_id="proc-003",
            title="Raw Socket Creation Denial (CAP_NET_RAW)",
            description="Verifies that unprivileged agents cannot create raw network sockets.",
            category="process",
            threat="Raw packet crafting, spoofing, or network sniffing via SOCK_RAW",
            expected_behavior="Raw socket creation must fail with EPERM due to dropped CAP_NET_RAW.",
            expected_verdict=Verdict.PASS,
            source=PROC_RAW_SOCKET_PROBE,
        ),
    ]


def get_scenario_by_id(scenario_id: str) -> Scenario | None:
    """Retrieve a scenario by its unique identifier."""
    for s in get_default_scenarios():
        if s.scenario_id.lower() == scenario_id.lower():
            return s
    return None


__all__ = ["get_default_scenarios", "get_scenario_by_id"]
