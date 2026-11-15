from observatory.evidence.models import AssessmentReport, ScenarioResult, Verdict
from observatory.reports import export_report, load_report, validate_report_json


def test_export_and_load_report(tmp_path):
    report = AssessmentReport(
        assessment_id="test-rep-001",
        runtime="docker",
        results=[
            ScenarioResult(
                scenario_id="fs-001",
                title="Root FS",
                verdict=Verdict.PASS,
                reason="Write blocked",
            )
        ],
    )

    out_file = tmp_path / "subdir" / "test_report.json"
    saved = export_report(report, out_file)

    assert saved.exists()
    loaded = load_report(saved)

    assert loaded.assessment_id == "test-rep-001"
    assert loaded.runtime == "docker"
    assert len(loaded.results) == 1
    assert loaded.results[0].scenario_id == "fs-001"
    assert loaded.results[0].verdict == Verdict.PASS


def test_validate_report_json():
    json_str = '{"assessment_id": "v-1", "runtime": "docker", "results": []}'
    validated = validate_report_json(json_str)
    assert validated.assessment_id == "v-1"
