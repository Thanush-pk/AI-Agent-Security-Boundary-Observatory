import pytest

from observatory.engine.assessment_engine import AssessmentEngine
from observatory.evidence.models import EvidenceSource, Verdict
from observatory.forensics import RegressionType, compare_assessments
from observatory.runtime.docker_runtime import DockerRuntime, DockerRuntimeError
from observatory.scenarios import get_default_scenarios, get_scenario_by_id


@pytest.fixture(scope="module")
def docker_runtime():
    instance = DockerRuntime(timeout_seconds=10)
    try:
        instance.check_available()
    except DockerRuntimeError as exc:
        pytest.skip(str(exc))
    return instance


def test_complete_end_to_end_assessment_all_boundaries(docker_runtime):
    scenarios = get_default_scenarios()
    assert len(scenarios) == 9

    # Verify categories are populated
    categories = {s.category for s in scenarios}
    assert categories == {"filesystem", "network", "process"}

    engine = AssessmentEngine(runtime=docker_runtime, runtime_name="docker")
    report = engine.run_assessment(scenarios)

    assert report.assessment_id.startswith("assess-")
    assert report.runtime == "docker"
    assert len(report.results) == 9

    for result in report.results:
        # All baseline boundary checks are expected to pass under the hardened DockerRuntime
        assert result.verdict == Verdict.PASS, f"{result.scenario_id} failed: {result.reason}"
        assert len(result.evidence) >= 2

        evidence_sources = {e.source for e in result.evidence}
        assert EvidenceSource.TEST_OBSERVATION in evidence_sources
        assert EvidenceSource.RUNTIME_LOG in evidence_sources

        # Find the structured observation record
        observation = next(
            e for e in result.evidence if e.source == EvidenceSource.TEST_OBSERVATION
        )
        assert observation.data.get("boundary_held") is True
        assert "threat" in observation.data
        assert "expected_behavior" in observation.data

    assert report.summary == {"pass": 9, "fail": 0, "inconclusive": 0}


def test_filesystem_boundary_tests_individually(docker_runtime):
    fs_scenarios = [s for s in get_default_scenarios() if s.category == "filesystem"]
    assert len(fs_scenarios) == 3

    engine = AssessmentEngine(runtime=docker_runtime, runtime_name="docker")
    for scenario in fs_scenarios:
        res = engine.run_scenario(scenario)
        assert res.verdict == Verdict.PASS


def test_network_boundary_tests_individually(docker_runtime):
    net_scenarios = [s for s in get_default_scenarios() if s.category == "network"]
    assert len(net_scenarios) == 3

    engine = AssessmentEngine(runtime=docker_runtime, runtime_name="docker")
    for scenario in net_scenarios:
        res = engine.run_scenario(scenario)
        assert res.verdict == Verdict.PASS


def test_privilege_boundary_tests_individually(docker_runtime):
    proc_scenarios = [s for s in get_default_scenarios() if s.category == "process"]
    assert len(proc_scenarios) == 3

    engine = AssessmentEngine(runtime=docker_runtime, runtime_name="docker")
    for scenario in proc_scenarios:
        res = engine.run_scenario(scenario)
        assert res.verdict == Verdict.PASS


def test_controlled_negative_test_in_permissive_environment():
    """Controlled negative test: deliberately execute scenarios in a permissive environment
    where the prohibited action succeeds. The evaluator must detect the violation and report FAIL."""
    permissive_runtime = DockerRuntime.create_permissive_test_runtime(
        read_only=False,
        network_disabled=False,
        user="0:0",
    )
    try:
        permissive_runtime.check_available()
    except DockerRuntimeError as exc:
        pytest.skip(str(exc))

    engine = AssessmentEngine(runtime=permissive_runtime, runtime_name="permissive-docker")

    # 1. Negative test for fs-001 (Root write prohibited):
    # In permissive container, file write succeeds, proving boundary violation is detected as FAIL
    fs_scenario = get_scenario_by_id("fs-001")
    assert fs_scenario is not None

    result = engine.run_scenario(fs_scenario)
    assert result.verdict == Verdict.FAIL
    assert "Security boundary violated" in result.reason
    assert "File successfully written" in result.reason

    obs_fs = next(e for e in result.evidence if e.source == EvidenceSource.TEST_OBSERVATION)
    assert obs_fs.data["boundary_held"] is False
    assert obs_fs.data["observed_behavior"] == "Successfully wrote to /test_boundary.txt"

    # 2. Negative test for proc-001 (Root execution prohibited):
    # In permissive container with user="0:0", root UID is detected, causing FAIL
    proc_scenario = get_scenario_by_id("proc-001")
    assert proc_scenario is not None

    proc_result = engine.run_scenario(proc_scenario)
    assert proc_result.verdict == Verdict.FAIL
    assert "Security boundary violated" in proc_result.reason

    obs_proc = next(e for e in proc_result.evidence if e.source == EvidenceSource.TEST_OBSERVATION)
    assert obs_proc.data["boundary_held"] is False
    assert obs_proc.data["uid"] == 0


def test_validate_regression_detection_with_different_live_reports(docker_runtime):
    """Validate regression detection by comparing a live hardened baseline report against a live permissive report containing deliberately failing boundaries."""
    permissive_runtime = DockerRuntime.create_permissive_test_runtime(
        read_only=False,
        user="0:0",
    )

    hardened_engine = AssessmentEngine(runtime=docker_runtime, runtime_name="docker-hardened")
    permissive_engine = AssessmentEngine(runtime=permissive_runtime, runtime_name="docker-permissive")

    test_scenarios = [get_scenario_by_id("fs-001"), get_scenario_by_id("proc-001")]

    baseline_report = hardened_engine.run_assessment(test_scenarios, assessment_id="assess-baseline")
    compromised_report = permissive_engine.run_assessment(test_scenarios, assessment_id="assess-compromised")

    # Verify baseline passed both
    assert baseline_report.results[0].verdict == Verdict.PASS
    assert baseline_report.results[1].verdict == Verdict.PASS

    # Verify permissive failed both
    assert compromised_report.results[0].verdict == Verdict.FAIL
    assert compromised_report.results[1].verdict == Verdict.FAIL

    # Run regression comparison
    comparison = compare_assessments(baseline_report, compromised_report)

    assert comparison.has_security_regressions is True
    assert comparison.regression_count == 2

    # Check scenario deltas
    delta_fs = next(d for d in comparison.deltas if d.scenario_id == "fs-001")
    assert delta_fs.regression_type == RegressionType.SECURITY_REGRESSION
    assert delta_fs.baseline_verdict == Verdict.PASS
    assert delta_fs.current_verdict == Verdict.FAIL
    assert "SECURITY REGRESSION" in delta_fs.message

    delta_proc = next(d for d in comparison.deltas if d.scenario_id == "proc-001")
    assert delta_proc.regression_type == RegressionType.SECURITY_REGRESSION
    assert delta_proc.baseline_verdict == Verdict.PASS
    assert delta_proc.current_verdict == Verdict.FAIL
