import subprocess

import pytest

from observatory.runtime import openshell_runtime
from observatory.runtime.openshell_runtime import (
    OpenShellRuntime,
    OpenShellRuntimeError,
)


def _fake_run(calls, result=None, timeout_on_create=False):
    def run(cmd, **kwargs):
        calls.append(cmd)
        if "create" in cmd and timeout_on_create:
            raise subprocess.TimeoutExpired(cmd, kwargs["timeout"])
        return result or subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    return run


def test_run_python_merges_output_and_keeps_exit_code(monkeypatch):
    calls = []
    done = subprocess.CompletedProcess([], 3, stdout='{"boundary_held": true}\n', stderr="note\n")
    monkeypatch.setattr(subprocess, "run", _fake_run(calls, done))

    result = OpenShellRuntime().run_python("print(1)")

    assert result.exit_code == 3 and not result.timed_out
    assert result.output == '{"boundary_held": true}\nnote\n'
    assert calls[0][-3:] == ["python", "-c", "print(1)"]
    assert "--no-keep" in calls[0]
    assert len(calls[0][calls[0].index("--name") + 1]) <= 19  # OpenShell name limit


def test_timeout_deletes_sandbox_and_reports_timed_out(monkeypatch):
    calls = []
    monkeypatch.setattr(subprocess, "run", _fake_run(calls, timeout_on_create=True))

    result = OpenShellRuntime().run_python("while True: pass")

    assert result.timed_out
    assert calls[-1][:3] == ["openshell", "sandbox", "delete"]


def test_check_available_requires_cli(monkeypatch):
    monkeypatch.setattr(openshell_runtime.shutil, "which", lambda _: None)
    with pytest.raises(OpenShellRuntimeError):
        OpenShellRuntime().check_available()


def test_rejects_empty_and_oversized_source():
    runtime = OpenShellRuntime()
    with pytest.raises(ValueError):
        runtime.run_python("  ")
    with pytest.raises(ValueError):
        runtime.run_python("x" * (32 * 1024 + 1))
