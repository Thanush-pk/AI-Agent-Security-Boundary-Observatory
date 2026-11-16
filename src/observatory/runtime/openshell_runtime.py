import shutil
import subprocess
import uuid

from observatory.runtime.base import ExecutionResult, RuntimeBackendError

MAX_ARG_BYTES = 32 * 1024  # OpenShell limits each command argument to 32 KiB.


class OpenShellRuntimeError(RuntimeBackendError):
    """Raised when the OpenShell CLI or gateway cannot be used."""


class OpenShellRuntime:
    """Run probes in disposable OpenShell sandboxes via the `openshell` CLI."""

    def __init__(
        self,
        image: str = "python:3.12-slim",
        memory_limit: str = "128Mi",
        cpu_limit: str = "500m",
        timeout_seconds: int = 10,
        # shortcut: fixed grace for sandbox start-up (image pull), upgrade by
        # splitting create and exec so only the probe itself is timed.
        startup_grace_seconds: int = 60,
    ) -> None:
        if timeout_seconds < 1:
            raise ValueError("timeout_seconds must be at least 1")
        self.image = image
        self.memory_limit = memory_limit
        self.cpu_limit = cpu_limit
        self.timeout_seconds = timeout_seconds
        self.startup_grace_seconds = startup_grace_seconds

    def check_available(self) -> bool:
        """Return True when the CLI is installed and the gateway answers."""
        if shutil.which("openshell") is None:
            raise OpenShellRuntimeError("The 'openshell' CLI is not installed.")
        try:
            status = subprocess.run(
                ["openshell", "status"],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise OpenShellRuntimeError("'openshell status' timed out.") from exc
        if status.returncode != 0:
            raise OpenShellRuntimeError(
                f"OpenShell gateway not ready: {(status.stdout + status.stderr).strip()}"
            )
        return True

    def run_python(self, source: str) -> ExecutionResult:
        """Execute Python source in a throwaway sandbox that is deleted afterwards."""
        if not source.strip():
            raise ValueError("source must not be empty")
        if len(source.encode()) > MAX_ARG_BYTES:
            raise ValueError("source exceeds OpenShell's 32 KiB argument limit")

        name = f"obs-{uuid.uuid4().hex[:8]}"  # OpenShell caps names at 19 chars
        cmd = [
            "openshell", "--color", "never", "sandbox", "create",
            "--name", name, "--no-keep", "--no-tty",
            "--from", self.image,
            "--cpu", self.cpu_limit, "--memory", self.memory_limit,
            "--", "python", "-c", source,
        ]
        try:
            done = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                errors="replace",
                stdin=subprocess.DEVNULL,
                timeout=self.timeout_seconds + self.startup_grace_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired:
            self._delete(name)
            return ExecutionResult(
                exit_code=-1,
                output="Execution exceeded the configured timeout.",
                timed_out=True,
            )
        except OSError as exc:
            raise OpenShellRuntimeError(f"Cannot run 'openshell': {exc}") from exc

        # stdout + stderr merged, like DockerRuntime's container logs.
        return ExecutionResult(exit_code=done.returncode, output=done.stdout + done.stderr)

    @staticmethod
    def _delete(name: str) -> None:
        """Best-effort cleanup of a sandbox left behind by a killed CLI."""
        try:
            subprocess.run(
                ["openshell", "sandbox", "delete", name],
                capture_output=True,
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            pass
