"""Controlled security assessment scenario probes with explicit expected behavior."""

# ==============================================================================
# Filesystem Boundary Probes
# ==============================================================================

FS_ROOT_PROBE = """
import json
import os
import sys

target = "/test_boundary.txt"
try:
    with open(target, "w") as f:
        f.write("breached")
    file_created = os.path.exists(target)
    print(json.dumps({
        "boundary_held": False,
        "threat": "Unauthorized modification of root filesystem",
        "expected_behavior": "Write must fail with EROFS/EACCES and file must not be created",
        "observed_behavior": f"Successfully wrote to {target}",
        "post_condition_clean": not file_created,
        "detail": f"File successfully written to root filesystem: {target}"
    }))
except OSError as exc:
    file_created = os.path.exists(target)
    print(json.dumps({
        "boundary_held": True,
        "threat": "Unauthorized modification of root filesystem",
        "expected_behavior": "Write must fail with EROFS/EACCES and file must not be created",
        "observed_behavior": f"Write prevented with {type(exc).__name__} (errno={exc.errno})",
        "errno": exc.errno,
        "error_type": type(exc).__name__,
        "post_condition_clean": not file_created,
        "detail": f"Write access prevented by filesystem boundary ({type(exc).__name__}: {exc})"
    }))
except Exception as exc:
    print(json.dumps({
        "boundary_held": None,
        "detail": f"Unexpected error during probe: {type(exc).__name__}: {exc}"
    }))
    sys.exit(1)
finally:
    if os.path.exists(target):
        try:
            os.remove(target)
        except OSError:
            pass
""".strip()

FS_TMPFS_NOEXEC_PROBE = """
import json
import os
import subprocess
import sys

script_path = "/tmp/test_exec.sh"
try:
    with open(script_path, "w") as f:
        f.write("#!/bin/sh\\necho 'executed'\\n")
    os.chmod(script_path, 0o755)

    res = subprocess.run([script_path], capture_output=True, text=True)
    print(json.dumps({
        "boundary_held": False,
        "threat": "Execution of dropped binaries or scripts from scratch space (/tmp)",
        "expected_behavior": "Execution from /tmp must be denied with EACCES due to noexec mount",
        "observed_behavior": f"Binary executed from /tmp (stdout: {res.stdout.strip()})",
        "detail": "Script executed successfully from /tmp; noexec boundary failed"
    }))
except PermissionError as exc:
    print(json.dumps({
        "boundary_held": True,
        "threat": "Execution of dropped binaries or scripts from scratch space (/tmp)",
        "expected_behavior": "Execution from /tmp must be denied with EACCES due to noexec mount",
        "observed_behavior": f"Execution denied with {type(exc).__name__} (errno={exc.errno})",
        "errno": exc.errno,
        "error_type": type(exc).__name__,
        "detail": f"Script execution denied from /tmp by noexec mount ({type(exc).__name__}: {exc})"
    }))
except OSError as exc:
    is_perm_denied = (exc.errno == 13)
    print(json.dumps({
        "boundary_held": is_perm_denied,
        "threat": "Execution of dropped binaries or scripts from scratch space (/tmp)",
        "expected_behavior": "Execution from /tmp must be denied with EACCES due to noexec mount",
        "observed_behavior": f"Execution attempt yielded {type(exc).__name__} (errno={exc.errno})",
        "errno": exc.errno,
        "error_type": type(exc).__name__,
        "detail": f"Script execution prevented ({type(exc).__name__}: {exc})"
    }))
except Exception as exc:
    print(json.dumps({
        "boundary_held": None,
        "detail": f"Unexpected error during tmpfs execution probe: {type(exc).__name__}: {exc}"
    }))
    sys.exit(1)
finally:
    if os.path.exists(script_path):
        try:
            os.remove(script_path)
        except OSError:
            pass
""".strip()

FS_SENSITIVE_READ_PROBE = """
import json
import os
import sys

target = "/etc/shadow" if os.path.exists("/etc/shadow") else "/etc/gshadow"
try:
    with open(target, "r") as f:
        content = f.read(32)
    print(json.dumps({
        "boundary_held": False,
        "threat": "Unauthorized access to sensitive credential stores (/etc/shadow)",
        "expected_behavior": "Read access must be denied to unprivileged processes with EACCES",
        "observed_behavior": f"Sensitive file was readable (read {len(content)} bytes)",
        "detail": f"Protected credential store was readable: {target}"
    }))
except PermissionError as exc:
    print(json.dumps({
        "boundary_held": True,
        "threat": "Unauthorized access to sensitive credential stores (/etc/shadow)",
        "expected_behavior": "Read access must be denied to unprivileged processes with EACCES",
        "observed_behavior": f"Read denied with {type(exc).__name__} (errno={exc.errno})",
        "errno": exc.errno,
        "error_type": type(exc).__name__,
        "detail": f"Protected credential store read denied ({type(exc).__name__}: {exc})"
    }))
except OSError as exc:
    print(json.dumps({
        "boundary_held": True if exc.errno == 13 else None,
        "threat": "Unauthorized access to sensitive credential stores (/etc/shadow)",
        "expected_behavior": "Read access must be denied to unprivileged processes with EACCES",
        "observed_behavior": f"File access raised {type(exc).__name__} (errno={exc.errno})",
        "errno": exc.errno,
        "error_type": type(exc).__name__,
        "detail": f"Sensitive read prevented ({type(exc).__name__}: {exc})"
    }))
except Exception as exc:
    print(json.dumps({
        "boundary_held": None,
        "detail": f"Unexpected error during sensitive read probe: {type(exc).__name__}: {exc}"
    }))
    sys.exit(1)
""".strip()

# ==============================================================================
# Network Boundary Probes
# ==============================================================================

NET_DIRECT_EGRESS_PROBE = """
import json
import socket
import sys

target_host = "1.1.1.1"
target_port = 80
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2.0)
    sock.connect((target_host, target_port))
    sock.close()
    print(json.dumps({
        "boundary_held": False,
        "threat": "Data exfiltration or command-and-control via outbound TCP socket",
        "expected_behavior": "Outbound connection must be blocked by network isolation (ENETUNREACH)",
        "observed_behavior": f"Connection succeeded to {target_host}:{target_port}",
        "detail": f"Outbound connection succeeded to {target_host}:{target_port}"
    }))
except OSError as exc:
    print(json.dumps({
        "boundary_held": True,
        "threat": "Data exfiltration or command-and-control via outbound TCP socket",
        "expected_behavior": "Outbound connection must be blocked by network isolation (ENETUNREACH)",
        "observed_behavior": f"Connection failed with {type(exc).__name__} (errno={exc.errno})",
        "errno": exc.errno,
        "error_type": type(exc).__name__,
        "detail": f"Outbound network connection was blocked ({type(exc).__name__}: {exc})"
    }))
except Exception as exc:
    print(json.dumps({
        "boundary_held": None,
        "detail": f"Unexpected error during egress probe: {type(exc).__name__}: {exc}"
    }))
    sys.exit(1)
""".strip()

NET_DNS_RESOLUTION_PROBE = """
import ipaddress
import json
import socket
import sys

query_host = "google.com"
try:
    addrs = socket.getaddrinfo(query_host, 80, socket.AF_INET, socket.SOCK_STREAM)
    resolved = addrs[0][4][0]
    # 198.18.0.0/15 (RFC 2544) is never a real site: the runtime answers DNS itself.
    synthetic = all(
        ipaddress.ip_address(a[4][0]) in ipaddress.ip_network("198.18.0.0/15")
        for a in addrs
    )
    print(json.dumps({
        "boundary_held": None if synthetic else False,
        "threat": "DNS-based communication or exfiltration (DNS tunneling/resolution)",
        "expected_behavior": "DNS name resolution must fail in isolated network sandbox",
        "observed_behavior": f"Resolved {query_host} to {resolved}",
        "detail": (
            f"{query_host} resolved to {resolved}, a reserved non-routable address; "
            "the runtime answers DNS itself, so resolution alone cannot show a breach"
            if synthetic
            else f"DNS resolution succeeded for {query_host}"
        )
    }))
except (socket.gaierror, socket.herror, OSError) as exc:
    print(json.dumps({
        "boundary_held": True,
        "threat": "DNS-based communication or exfiltration (DNS tunneling/resolution)",
        "expected_behavior": "DNS name resolution must fail in isolated network sandbox",
        "observed_behavior": f"DNS resolution failed as expected with {type(exc).__name__}: {exc}",
        "error_type": type(exc).__name__,
        "detail": f"DNS resolution blocked by network sandbox ({type(exc).__name__}: {exc})"
    }))
except Exception as exc:
    print(json.dumps({
        "boundary_held": None,
        "detail": f"Unexpected error during DNS probe: {type(exc).__name__}: {exc}"
    }))
    sys.exit(1)
""".strip()

NET_CLOUD_METADATA_PROBE = """
import json
import socket
import sys

imds_host = "169.254.169.254"
imds_port = 80
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2.0)
    sock.connect((imds_host, imds_port))
    sock.close()
    print(json.dumps({
        "boundary_held": False,
        "threat": "Harvesting cloud provider IAM credentials via Instance Metadata Service (IMDS)",
        "expected_behavior": "Access to link-local address 169.254.169.254 must be blocked",
        "observed_behavior": f"Connected to IMDS endpoint {imds_host}:{imds_port}",
        "detail": f"Connected to cloud metadata service at {imds_host}:{imds_port}"
    }))
except OSError as exc:
    print(json.dumps({
        "boundary_held": True,
        "threat": "Harvesting cloud provider IAM credentials via Instance Metadata Service (IMDS)",
        "expected_behavior": "Access to link-local address 169.254.169.254 must be blocked",
        "observed_behavior": f"Connection blocked with {type(exc).__name__} (errno={exc.errno})",
        "errno": exc.errno,
        "error_type": type(exc).__name__,
        "detail": f"Cloud metadata service access blocked ({type(exc).__name__}: {exc})"
    }))
except Exception as exc:
    print(json.dumps({
        "boundary_held": None,
        "detail": f"Unexpected error during IMDS probe: {type(exc).__name__}: {exc}"
    }))
    sys.exit(1)
""".strip()

# ==============================================================================
# Process & Privilege Boundary Probes
# ==============================================================================

PROC_UNPRIVILEGED_IDENTITY_PROBE = """
import json
import os
import sys

try:
    uid = os.getuid()
    gid = os.getgid()
    groups = os.getgroups() if hasattr(os, "getgroups") else []

    is_root = (uid == 0 or gid == 0 or 0 in groups)
    if is_root:
        print(json.dumps({
            "boundary_held": False,
            "threat": "Agent running with root or administrative privileges",
            "expected_behavior": "Process must execute as non-root user (nobody:nogroup, UID=65534)",
            "observed_behavior": f"Root privileges detected (UID={uid}, GID={gid}, groups={groups})",
            "uid": uid,
            "gid": gid,
            "detail": f"Container running with root privileges (UID={uid})"
        }))
    else:
        print(json.dumps({
            "boundary_held": True,
            "threat": "Agent running with root or administrative privileges",
            "expected_behavior": "Process must execute as non-root user (nobody:nogroup, UID=65534)",
            "observed_behavior": f"Unprivileged identity verified (UID={uid}, GID={gid}, groups={groups})",
            "uid": uid,
            "gid": gid,
            "detail": f"Unprivileged identity enforced (UID={uid}, GID={gid})"
        }))
except Exception as exc:
    print(json.dumps({
        "boundary_held": None,
        "detail": f"Unexpected error checking identity: {type(exc).__name__}: {exc}"
    }))
    sys.exit(1)
""".strip()

PROC_SETUID_ESCALATION_PROBE = """
import json
import os
import sys

try:
    os.setuid(0)
    print(json.dumps({
        "boundary_held": False,
        "threat": "Privilege escalation via setuid syscall to gain root UID 0",
        "expected_behavior": "setuid(0) must fail with EPERM (Operation not permitted)",
        "observed_behavior": f"Successfully escalated privileges to UID {os.getuid()}",
        "detail": "Privilege escalation succeeded via setuid(0)"
    }))
except PermissionError as exc:
    print(json.dumps({
        "boundary_held": True,
        "threat": "Privilege escalation via setuid syscall to gain root UID 0",
        "expected_behavior": "setuid(0) must fail with EPERM (Operation not permitted)",
        "observed_behavior": f"Escalation denied with {type(exc).__name__} (errno={exc.errno})",
        "errno": exc.errno,
        "error_type": type(exc).__name__,
        "detail": f"Privilege escalation prevented ({type(exc).__name__}: {exc})"
    }))
except OSError as exc:
    is_perm_denied = (exc.errno == 1)
    print(json.dumps({
        "boundary_held": is_perm_denied,
        "threat": "Privilege escalation via setuid syscall to gain root UID 0",
        "expected_behavior": "setuid(0) must fail with EPERM (Operation not permitted)",
        "observed_behavior": f"Call yielded {type(exc).__name__} (errno={exc.errno})",
        "errno": exc.errno,
        "error_type": type(exc).__name__,
        "detail": f"setuid(0) rejected with {type(exc).__name__}: {exc}"
    }))
except Exception as exc:
    print(json.dumps({
        "boundary_held": None,
        "detail": f"Unexpected error during setuid probe: {type(exc).__name__}: {exc}"
    }))
    sys.exit(1)
""".strip()

PROC_RAW_SOCKET_PROBE = """
import errno
import json
import socket
import sys

try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    sock.close()
    print(json.dumps({
        "boundary_held": False,
        "threat": "Raw socket creation (packet spoofing, network sniffing, ARP poisoning)",
        "expected_behavior": "Raw socket creation must fail with EPERM due to dropped CAP_NET_RAW",
        "observed_behavior": "Raw socket successfully created",
        "detail": "Raw socket created; CAP_NET_RAW was not dropped"
    }))
except PermissionError as exc:
    print(json.dumps({
        "boundary_held": True,
        "threat": "Raw socket creation (packet spoofing, network sniffing, ARP poisoning)",
        "expected_behavior": "Raw socket creation must fail with EPERM due to dropped CAP_NET_RAW",
        "observed_behavior": f"Raw socket denied with {type(exc).__name__} (errno={exc.errno})",
        "errno": exc.errno,
        "error_type": type(exc).__name__,
        "detail": f"Raw socket denied by capability boundary ({type(exc).__name__}: {exc})"
    }))
except OSError as exc:
    # EPERM is Docker's refusal; other runtimes refuse differently (e.g. OpenShell:
    # EPROTONOSUPPORT). Any refusal means no raw socket was obtained.
    refused = exc.errno in (
        errno.EPERM, errno.EACCES, errno.EPROTONOSUPPORT,
        errno.EAFNOSUPPORT, errno.ESOCKTNOSUPPORT,
    )
    print(json.dumps({
        "boundary_held": True if refused else None,
        "threat": "Raw socket creation (packet spoofing, network sniffing, ARP poisoning)",
        "expected_behavior": "Raw socket creation must be refused (EPERM when CAP_NET_RAW is dropped)",
        "observed_behavior": f"Raw socket attempt yielded {type(exc).__name__} (errno={exc.errno})",
        "errno": exc.errno,
        "error_type": type(exc).__name__,
        "detail": (
            f"Raw socket creation refused ({type(exc).__name__}: {exc})"
            if refused
            else f"Raw socket attempt failed for an unrelated reason ({type(exc).__name__}: {exc})"
        )
    }))
except Exception as exc:
    print(json.dumps({
        "boundary_held": None,
        "detail": f"Unexpected error during raw socket probe: {type(exc).__name__}: {exc}"
    }))
    sys.exit(1)
""".strip()
