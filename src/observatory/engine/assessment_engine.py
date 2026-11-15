import uuid
from collections.abc import Sequence
from datetime import UTC, datetime

from observatory.engine.scenario import Scenario
from observatory.evidence.models import AssessmentReport, ScenarioResult
from observatory.runtime.base import Runtime


class AssessmentEngine:
    """Orchestrates security scenarios against a runtime and collects evidence into an AssessmentReport."""

    def __init__(self, runtime: Runtime, runtime_name: str = "docker") -> None:
        self.runtime = runtime
        self.runtime_name = runtime_name

    def run_scenario(self, scenario: Scenario) -> ScenarioResult:
        """Execute a single scenario inside the runtime environment and produce its verdict and evidence."""
        execution = self.runtime.run_python(scenario.source)
        return scenario.evaluate(execution)

    def run_assessment(
        self,
        scenarios: Sequence[Scenario],
        assessment_id: str | None = None,
    ) -> AssessmentReport:
        """Run a suite of security scenarios and assemble an AssessmentReport."""
        if assessment_id is None:
            assessment_id = f"assess-{uuid.uuid4().hex[:8]}"

        started_at = datetime.now(UTC)
        results: list[ScenarioResult] = []

        for scenario in scenarios:
            result = self.run_scenario(scenario)
            results.append(result)

        return AssessmentReport(
            assessment_id=assessment_id,
            runtime=self.runtime_name,
            started_at=started_at,
            results=results,
        )
