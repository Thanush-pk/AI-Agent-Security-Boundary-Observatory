import pytest
from typer.testing import CliRunner

from observatory.cli import app
from observatory.evidence.models import AssessmentReport, ScenarioResult, Verdict
from observatory.reports import export_report, render_html


def make_report(runtime, verdict, reason="ok"):
    return AssessmentReport(
        assessment_id=f"assess-{runtime}",
        runtime=runtime,
        results=[
            ScenarioResult(
                scenario_id="fs-001", title="Root FS", verdict=verdict, reason=reason
            )
        ],
    )


def test_page_shows_each_runtime_and_verdict_as_text():
    page = render_html(
        [make_report("docker", Verdict.PASS), make_report("openshell", Verdict.FAIL)]
    )
    assert "docker" in page and "openshell" in page
    assert "✓ PASS" in page and "✗ FAIL" in page
    assert "fs-001" in page and "Root FS" in page


def test_report_text_is_escaped():
    page = render_html(
        [make_report("docker", Verdict.PASS, reason="<script>alert(1)</script>")]
    )
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;" in page


def test_render_requires_a_report():
    with pytest.raises(ValueError):
        render_html([])


def test_cli_writes_html_file(tmp_path):
    report_file = export_report(make_report("docker", Verdict.PASS), tmp_path / "r.json")
    out = tmp_path / "out" / "page.html"

    result = CliRunner().invoke(app, ["html", str(report_file), "-o", str(out)])

    assert result.exit_code == 0
    assert out.read_text(encoding="utf-8").startswith("<!doctype html>")


def test_cli_reports_missing_file(tmp_path):
    result = CliRunner().invoke(app, ["html", str(tmp_path / "missing.json")])
    assert result.exit_code == 1
