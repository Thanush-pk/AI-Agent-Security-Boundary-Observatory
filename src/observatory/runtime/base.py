from typing import Protocol

from observatory.runtime.docker_runtime import ExecutionResult


class Runtime(Protocol):
    """Protocol for isolated agent execution environments."""

    def check_available(self) -> bool:
        """Return True when the runtime environment is reachable."""
        ...

    def run_python(self, source: str) -> ExecutionResult:
        """Execute Python source code inside the runtime."""
        ...
