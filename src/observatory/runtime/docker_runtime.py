import docker
from docker.errors import DockerException, ImageNotFound
from requests.exceptions import ReadTimeout

from observatory.runtime.base import ExecutionResult


class DockerRuntimeError(RuntimeError):
    """Raised when the Docker runtime cannot execute a scenario."""


class DockerRuntime:
    """Run controlled Python scenarios in restricted, disposable containers."""

    def __init__(
        self,
        image: str = "python:3.12-slim",
        memory_limit: str = "128m",
        timeout_seconds: int = 10,
        read_only: bool = True,
        network_disabled: bool = True,
        user: str = "65534:65534",
        cap_drop: list[str] | None = None,
        security_opt: list[str] | None = None,
        tmpfs: dict[str, str] | None = None,
    ) -> None:
        if timeout_seconds < 1:
            raise ValueError("timeout_seconds must be at least 1")

        self.image = image
        self.memory_limit = memory_limit
        self.timeout_seconds = timeout_seconds
        self.read_only = read_only
        self.network_disabled = network_disabled
        self.user = user
        self.cap_drop = ["ALL"] if cap_drop is None else cap_drop
        self.security_opt = (
            ["no-new-privileges:true"] if security_opt is None else security_opt
        )
        self.tmpfs = (
            {"/tmp": "rw,noexec,nosuid,size=16m"} if tmpfs is None else tmpfs
        )

    @classmethod
    def create_permissive_test_runtime(
        cls,
        read_only: bool = False,
        network_disabled: bool = False,
        user: str = "0:0",
        timeout_seconds: int = 10,
    ) -> "DockerRuntime":
        """Create a permissive container runtime strictly for negative testing of boundary defenses."""
        return cls(
            read_only=read_only,
            network_disabled=network_disabled,
            user=user,
            cap_drop=[],
            security_opt=[],
            tmpfs=None,
            timeout_seconds=timeout_seconds,
        )

    def check_available(self) -> bool:
        """Return True when the Docker daemon is reachable."""
        try:
            docker.from_env().ping()
            return True
        except DockerException as exc:
            raise DockerRuntimeError(
                "Cannot connect to Docker. Check Docker Desktop."
            ) from exc

    def run_python(self, source: str) -> ExecutionResult:
        """Execute Python source without host mounts or network access."""
        if not source.strip():
            raise ValueError("source must not be empty")

        client = docker.from_env()
        container = None

        try:
            client.ping()

            try:
                client.images.get(self.image)
            except ImageNotFound:
                client.images.pull(self.image)

            container = client.containers.run(
                image=self.image,
                command=["python", "-c", source],
                detach=True,
                network_disabled=self.network_disabled,
                read_only=self.read_only,
                tmpfs=self.tmpfs,
                cap_drop=self.cap_drop,
                security_opt=self.security_opt,
                mem_limit=self.memory_limit,
                nano_cpus=500_000_000,
                pids_limit=64,
                user=self.user,
                working_dir="/tmp",
                auto_remove=False,
            )

            try:
                state = container.wait(timeout=self.timeout_seconds)
                output = container.logs(
                    stdout=True, stderr=True
                ).decode("utf-8", errors="replace")

                return ExecutionResult(
                    exit_code=int(state["StatusCode"]),
                    output=output,
                )

            except ReadTimeout:
                container.kill()
                return ExecutionResult(
                    exit_code=-1,
                    output="Execution exceeded the configured timeout.",
                    timed_out=True,
                )

        except DockerRuntimeError:
            raise
        except DockerException as exc:
            raise DockerRuntimeError(
                f"Docker execution failed: {exc}"
            ) from exc
        finally:
            if container is not None:
                try:
                    container.remove(force=True)
                except DockerException:
                    pass
            client.close()
