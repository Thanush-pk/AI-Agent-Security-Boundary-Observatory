from datetime import UTC, datetime, timedelta

from observatory.evidence.models import (
    AssessmentReport,
    EvidenceRecord,
    EvidenceSource,
    ScenarioResult,
    Verdict,
)
from observatory.forensics import (
    RegressionType,
    compare_assessments,
    format_timeline_text,
    reconstruct_timeline,
)


def test_timeline_reconstruction_orders_events():
    t0 = datetime(2026, 1, 1, 10, 0, 0, tzinfo=UTC)
    t1 = t0 + timedelta(seconds=1)
    t2 = t0 + timedelta(seconds=2)

    report = AssessmentReport(
        assessment_id="rep-1",
        runtime="docker",
        started_at=t0,
        results=[
            ScenarioResult(
                scenario_id="fs-001",
                title="Root FS",
                verdict=Verdict.PASS,
                reason="Held",
                evidence=[
                    EvidenceRecord(
                        evidence_id="ev-2",
                        source=EvidenceSource.TEST_OBSERVATION,
                        observed_at=t2,
                        description="Probe confirmed blocked write",
                    ),
                    EvidenceRecord(
                        evidence_id="ev-1",
                        source=EvidenceSource.RUNTIME_LOG,
                        observed_at=t1,
                        description="Container logs",
                    ),
                ],
            )
        ],
    )

    events = reconstruct_timeline(report)
    assert len(events) == 3
    # Check strict chronological order
    assert events[0].timestamp <= events[1].timestamp <= events[2].timestamp
    assert events[0].event_type == "assessment_started"
    assert events[1].event_type == "runtime_log"
    assert events[2].event_type == "test_observation"

    formatted = format_timeline_text(events)
    assert "Incident & Assessment Timeline" in formatted
    assert "fs-001" in formatted


def test_compare_assessments_detects_regressions():
    baseline = AssessmentReport(
        assessment_id="run-base",
        runtime="docker",
        results=[
            ScenarioResult(
                scenario_id="fs-001",
                title="FS",
                verdict=Verdict.PASS,
                reason="Held",
            ),
            ScenarioResult(
                scenario_id="net-001",
                title="Net",
                verdict=Verdict.PASS,
                reason="Held",
            ),
            ScenarioResult(
                scenario_id="proc-001",
                title="Proc",
                verdict=Verdict.FAIL,
                reason="Breached previously",
            ),
        ],
    )

    current = AssessmentReport(
        assessment_id="run-curr",
        runtime="docker",
        results=[
            ScenarioResult(
                scenario_id="fs-001",
                title="FS",
                verdict=Verdict.FAIL,  # REGRESSION!
                reason="Breached now!",
            ),
            ScenarioResult(
                scenario_id="net-001",
                title="Net",
                verdict=Verdict.INCONCLUSIVE,  # DEGRADATION!
                reason="Timed out",
            ),
            ScenarioResult(
                scenario_id="proc-001",
                title="Proc",
                verdict=Verdict.PASS,  # IMPROVEMENT!
                reason="Fixed",
            ),
            ScenarioResult(
                scenario_id="new-001",
                title="New",
                verdict=Verdict.PASS,  # NEW SCENARIO!
                reason="Pass",
            ),
        ],
    )

    comparison = compare_assessments(baseline, current)

    assert comparison.has_security_regressions is True
    assert comparison.regression_count == 1
    assert comparison.degradation_count == 1
    assert comparison.improvement_count == 1

    deltas_by_id = {d.scenario_id: d for d in comparison.deltas}
    assert deltas_by_id["fs-001"].regression_type == RegressionType.SECURITY_REGRESSION
    assert deltas_by_id["net-001"].regression_type == RegressionType.DEGRADATION
    assert deltas_by_id["proc-001"].regression_type == RegressionType.IMPROVEMENT
    assert deltas_by_id["new-001"].regression_type == RegressionType.NEW_SCENARIO
