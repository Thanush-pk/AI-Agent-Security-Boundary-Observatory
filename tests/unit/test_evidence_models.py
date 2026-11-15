
from observatory.evidence.models import (
    AssessmentReport,
    EvidenceRecord,
    EvidenceSource,
    ScenarioResult,
    Verdict,
)


def test_assessment_summary_counts_each_verdict():
    report = AssessmentReport(
        assessment_id="test-001",
        runtime="docker",
        results=[
            ScenarioResult(
                scenario_id="fs-001",
                title="Workspace read",
                verdict=Verdict.PASS,
                reason="Expected behavior was observed.",
            ),
            ScenarioResult(
                scenario_id="fs-002",
                title="Protected file read",
                verdict=Verdict.FAIL,
                reason="The protected file was readable.",
            ),
            ScenarioResult(
                scenario_id="net-001",
                title="Network restriction",
                verdict=Verdict.INCONCLUSIVE,
                reason="Insufficient evidence.",
            ),
        ],
    )

    assert report.summary == {
        "pass": 1,
        "fail": 1,
        "inconclusive": 1,
    }


def test_evidence_record_captures_observation():
    evidence = EvidenceRecord(
        evidence_id="ev-001",
        source=EvidenceSource.TEST_OBSERVATION,
        description="The test process received an expected response.",
    )

    assert evidence.evidence_id == "ev-001"
    assert evidence.observed_at.tzinfo is not None
