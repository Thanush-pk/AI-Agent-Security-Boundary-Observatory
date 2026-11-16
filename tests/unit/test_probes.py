import errno
import socket

import pytest

from observatory.scenarios.builtin import (
    NET_DNS_RESOLUTION_PROBE,
    PROC_RAW_SOCKET_PROBE,
)
from observatory.verdicts.evaluator import parse_observation_payload


def run_probe(source, capsys):
    exec(source, {"__name__": "probe"})  # noqa: S102 - our own probe code
    return parse_observation_payload(capsys.readouterr().out)


def _answer(ip):
    return lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 80))]


@pytest.mark.parametrize(
    ("ip", "held"),
    [("198.18.0.2", None), ("142.250.1.1", False)],
)
def test_dns_probe_judges_resolved_address(monkeypatch, capsys, ip, held):
    monkeypatch.setattr(socket, "getaddrinfo", _answer(ip))
    assert run_probe(NET_DNS_RESOLUTION_PROBE, capsys)["boundary_held"] is held


def test_dns_probe_passes_when_lookup_fails(monkeypatch, capsys):
    def fail(*a, **k):
        raise socket.gaierror(-3, "no resolution")

    monkeypatch.setattr(socket, "getaddrinfo", fail)
    assert run_probe(NET_DNS_RESOLUTION_PROBE, capsys)["boundary_held"] is True


@pytest.mark.parametrize(
    ("code", "held"),
    [
        (errno.EPERM, True),
        (errno.EPROTONOSUPPORT, True),  # what OpenShell returns
        (errno.ENOBUFS, None),  # unrelated failure must not count as a PASS
    ],
)
def test_raw_socket_probe_classifies_errno(monkeypatch, capsys, code, held):
    def refuse(*a, **k):
        raise OSError(code, "refused")

    monkeypatch.setattr(socket, "socket", refuse)
    assert run_probe(PROC_RAW_SOCKET_PROBE, capsys)["boundary_held"] is held


def test_raw_socket_probe_fails_when_socket_is_created(monkeypatch, capsys):
    class Sock:
        def close(self):
            pass

    monkeypatch.setattr(socket, "socket", lambda *a, **k: Sock())
    assert run_probe(PROC_RAW_SOCKET_PROBE, capsys)["boundary_held"] is False
