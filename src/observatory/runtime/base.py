from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class ExecutionResult:
    """Observable outcome of one isolated execution, for any runtime."""

    exit_code: int
    output: str
    timed_out: bool = False


class Runtime(Protocol):
    """Protocol for isolated agent execution environments."""

    def check_available(self) -> bool:
        """Return True when the runtime environment is reachable."""
        ...

    def run_python(self, source: str) -> ExecutionResult:
        """Execute Python source code inside the runtime."""
        ...
