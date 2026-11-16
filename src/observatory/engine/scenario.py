from collections.abc import Callable
from dataclasses import dataclass

from observatory.evidence.models import ScenarioResult, Verdict
from observatory.runtime.base import ExecutionResult
from observatory.verdicts.evaluator import evaluate_boundary_execution


@dataclass
class Scenario:
    """Security test scenario executed against a runtime environment."""

    scenario_id: str
    title: str
    description: str
    category: str
    source: str
    threat: str = ""
    expected_behavior: str = ""
    expected_verdict: Verdict = Verdict.PASS
    evaluator: Callable[["Scenario", ExecutionResult], ScenarioResult] | None = None

    def evaluate(self, execution: ExecutionResult) -> ScenarioResult:
        """Evaluate the execution result to produce a ScenarioResult."""
        if self.evaluator is not None:
            return self.evaluator(self, execution)
        return evaluate_boundary_execution(
            scenario_id=self.scenario_id,
            title=self.title,
            execution=execution,
        )
