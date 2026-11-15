from observatory.evidence.models import EvidenceSource, Verdict
from observatory.runtime.docker_runtime import ExecutionResult
from observatory.verdicts.evaluator import evaluate_boundary_execution


def test_evaluator_handles_successful_boundary_defense():
    execution = ExecutionResult(
        exit_code=0,
        output='{"boundary_held": true, "detail": "Write prevented as expected."}',
    )

    result = evaluate_boundary_execution("fs-001", "Filesystem test", execution)

    assert result.verdict == Verdict.PASS
    assert "Write prevented as expected." in result.reason
    assert len(result.evidence) == 2
    sources = {e.source for e in result.evidence}
    assert EvidenceSource.TEST_OBSERVATION in sources
    assert EvidenceSource.RUNTIME_LOG in sources


def test_evaluator_handles_boundary_violation():
    execution = ExecutionResult(
        exit_code=0,
        output='{"boundary_held": false, "detail": "Root filesystem was written."}',
    )

    result = evaluate_boundary_execution("fs-001", "Filesystem test", execution)

    assert result.verdict == Verdict.FAIL
    assert "Security boundary violated" in result.reason
    assert len(result.evidence) == 2


def test_evaluator_handles_timeout():
    execution = ExecutionResult(
        exit_code=-1,
        output="Execution exceeded timeout.",
        timed_out=True,
    )

    result = evaluate_boundary_execution("fs-001", "Filesystem test", execution)

    assert result.verdict == Verdict.INCONCLUSIVE
    assert "timed out" in result.reason.lower()
    assert result.evidence[0].source == EvidenceSource.SYSTEM_ERROR


def test_evaluator_handles_unhandled_crash():
    execution = ExecutionResult(
        exit_code=1,
        output="Traceback (most recent call last):\nValueError: bad",
    )

    result = evaluate_boundary_execution("fs-001", "Filesystem test", execution)

    assert result.verdict == Verdict.INCONCLUSIVE
    assert "code 1" in result.reason
