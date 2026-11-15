from pathlib import Path
from typing import Annotated

import typer

from observatory.engine.assessment_engine import AssessmentEngine
from observatory.evidence.models import Verdict
from observatory.forensics import (
    RegressionType,
    compare_assessments,
    format_timeline_text,
    reconstruct_timeline,
)
from observatory.reports import export_report, load_report
from observatory.runtime.docker_runtime import DockerRuntime, DockerRuntimeError
from observatory.scenarios import get_default_scenarios, get_scenario_by_id

app = typer.Typer(
    name="observatory",
    help="Evidence-based security assessments for AI agent runtimes.",
)


@app.command()
def version() -> None:
    """Display the installed Observatory version."""
    typer.echo("Agent Boundary Observatory 0.1.0")


@app.command(name="scenarios")
def list_scenarios() -> None:
    """List available security scenarios with their threats and expected behavior."""
    scenarios = get_default_scenarios()
    typer.echo(f"\nAvailable Scenarios ({len(scenarios)}):\n")
    for s in scenarios:
        typer.echo(f"  [{s.scenario_id}] {s.title} ({s.category})")
        typer.echo(f"    Threat: {s.threat}")
        typer.echo(f"    Expected: {s.expected_behavior}\n")


@app.command(name="assess")
@app.command(name="run")
def run_assessment(
    scenario: Annotated[
        str | None,
        typer.Argument(help="Optional scenario ID to assess (e.g. fs-001). Default runs all."),
    ] = None,
    scenario_id: Annotated[
        str | None,
        typer.Option("--scenario", "-s", help="Optional specific scenario ID to assess"),
    ] = None,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="File path to save the JSON AssessmentReport"),
    ] = None,
    timeout: Annotated[
        int,
        typer.Option("--timeout", "-t", help="Timeout in seconds per scenario execution"),
    ] = 10,
) -> None:
    """Run security boundary assessments in isolated Docker containers."""
    runtime = DockerRuntime(timeout_seconds=timeout)
    try:
        runtime.check_available()
    except DockerRuntimeError as exc:
        typer.secho(f"Error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    target_id = scenario or scenario_id
    if target_id:
        target_scenario = get_scenario_by_id(target_id)
        if not target_scenario:
            typer.secho(f"Scenario '{target_id}' not found.", fg=typer.colors.RED, err=True)
            raise typer.Exit(code=1)
        scenarios = [target_scenario]
    else:
        scenarios = get_default_scenarios()

    engine = AssessmentEngine(runtime=runtime, runtime_name="docker")
    typer.echo(f"\nRunning assessment with {len(scenarios)} scenario(s) against DockerRuntime...\n")

    report = engine.run_assessment(scenarios)

    for result in report.results:
        if result.verdict == Verdict.PASS:
            color = typer.colors.GREEN
        elif result.verdict == Verdict.FAIL:
            color = typer.colors.RED
        else:
            color = typer.colors.YELLOW

        verdict_badge = typer.style(f"[{result.verdict.value}]", fg=color, bold=True)
        typer.echo(f"{verdict_badge} {result.scenario_id}: {result.title}")
        typer.echo(f"       Reason: {result.reason}")
        typer.echo(f"       Evidence records: {len(result.evidence)}\n")

    summary = report.summary
    typer.secho("Assessment Summary:", bold=True)
    typer.echo(
        f"  PASS: {summary['pass']} | FAIL: {summary['fail']} | INCONCLUSIVE: {summary['inconclusive']}"
    )

    if output:
        saved_path = export_report(report, output)
        typer.echo(f"\nReport saved to: {saved_path.resolve()}")

    if summary["fail"] > 0:
        raise typer.Exit(code=2)


@app.command(name="timeline")
def show_timeline(
    report_file: Annotated[
        Path,
        typer.Argument(help="Path to an exported AssessmentReport JSON file"),
    ],
) -> None:
    """Reconstruct and display a chronological incident timeline from assessment evidence."""
    try:
        report = load_report(report_file)
    except (OSError, ValueError) as exc:
        typer.secho(f"Failed to load report: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    events = reconstruct_timeline(report)
    timeline_text = format_timeline_text(events)
    typer.echo(f"\n{timeline_text}\n")
    typer.echo(f"Total reconstructed timeline events: {len(events)}")


@app.command(name="compare")
def compare_runs(
    baseline_file: Annotated[
        Path,
        typer.Argument(help="Path to baseline AssessmentReport JSON file"),
    ],
    current_file: Annotated[
        Path,
        typer.Argument(help="Path to current AssessmentReport JSON file"),
    ],
) -> None:
    """Compare two assessment runs to detect security regressions or degradations."""
    try:
        baseline = load_report(baseline_file)
        current = load_report(current_file)
    except (OSError, ValueError) as exc:
        typer.secho(f"Failed to load reports: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    comparison = compare_assessments(baseline, current)

    typer.echo("\nComparing Assessment Runs:")
    typer.echo(f"  Baseline: {comparison.baseline_id}")
    typer.echo(f"  Current:  {comparison.current_id}\n")

    for delta in comparison.deltas:
        if delta.regression_type == RegressionType.SECURITY_REGRESSION:
            prefix = typer.style("[REGRESSION]", fg=typer.colors.RED, bold=True)
        elif delta.regression_type in {RegressionType.DEGRADATION, RegressionType.FAILURE_DEGRADATION}:
            prefix = typer.style("[DEGRADED]  ", fg=typer.colors.YELLOW, bold=True)
        elif delta.regression_type == RegressionType.IMPROVEMENT:
            prefix = typer.style("[IMPROVED]  ", fg=typer.colors.GREEN, bold=True)
        else:
            prefix = typer.style("[UNCHANGED] ", fg=typer.colors.WHITE)

        b_val = delta.baseline_verdict.value if delta.baseline_verdict else "N/A"
        c_val = delta.current_verdict.value if delta.current_verdict else "N/A"
        typer.echo(f"{prefix} {delta.scenario_id:<10} ({b_val} -> {c_val}): {delta.message}")

    typer.echo("\nComparison Summary:")
    typer.echo(f"  Security Regressions: {comparison.regression_count}")
    typer.echo(f"  Degradations:         {comparison.degradation_count}")
    typer.echo(f"  Improvements:         {comparison.improvement_count}\n")

    if comparison.has_security_regressions:
        typer.secho("ALERT: Security regression detected!", fg=typer.colors.RED, bold=True)
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
