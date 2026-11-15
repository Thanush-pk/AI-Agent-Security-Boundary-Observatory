from observatory.engine.assessment_engine import AssessmentEngine
from observatory.engine.scenario import Scenario
from observatory.evidence.models import Verdict
from observatory.runtime.docker_runtime import ExecutionResult


class MockRuntime:
    def __init__(self, responses: dict[str, ExecutionResult]) -> None:
        self.responses = responses
        self.calls: list[str] = []

    def check_available(self) -> bool:
        return True

    def run_python(self, source: str) -> ExecutionResult:
        self.calls.append(source)
        return self.responses.get(
            source,
            ExecutionResult(exit_code=0, output='{"boundary_held": true, "detail": "ok"}'),
        )


def test_assessment_engine_runs_scenarios_and_aggregates_report():
    runtime = MockRuntime({
        "probe-1": ExecutionResult(
            exit_code=0,
            output='{"boundary_held": true, "detail": "Filesystem boundary held."}',
        ),
        "probe-2": ExecutionResult(
            exit_code=0,
            output='{"boundary_held": false, "detail": "Network egress allowed."}',
        ),
    })

    scenarios = [
        Scenario(
            scenario_id="test-1",
            title="FS test",
            description="desc",
            category="fs",
            source="probe-1",
        ),
        Scenario(
            scenario_id="test-2",
            title="Net test",
            description="desc",
            category="net",
            source="probe-2",
        ),
    ]

    engine = AssessmentEngine(runtime=runtime, runtime_name="mock")
    report = engine.run_assessment(scenarios, assessment_id="assess-100")

    assert report.assessment_id == "assess-100"
    assert report.runtime == "mock"
    assert len(report.results) == 2
    assert report.results[0].verdict == Verdict.PASS
    assert report.results[1].verdict == Verdict.FAIL
    assert report.summary == {"pass": 1, "fail": 1, "inconclusive": 0}
