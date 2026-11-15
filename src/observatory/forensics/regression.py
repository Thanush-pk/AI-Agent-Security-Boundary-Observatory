from dataclasses import dataclass, field
from enum import Enum

from observatory.evidence.models import AssessmentReport, Verdict


class RegressionType(str, Enum):
    SECURITY_REGRESSION = "SECURITY_REGRESSION"  # PASS -> FAIL
    DEGRADATION = "DEGRADATION"                  # PASS -> INCONCLUSIVE
    FAILURE_DEGRADATION = "FAILURE_DEGRADATION"  # INCONCLUSIVE -> FAIL
    IMPROVEMENT = "IMPROVEMENT"                  # FAIL/INCONCLUSIVE -> PASS
    UNCHANGED = "UNCHANGED"
    NEW_SCENARIO = "NEW_SCENARIO"
    REMOVED_SCENARIO = "REMOVED_SCENARIO"


@dataclass(frozen=True)
class ScenarioDelta:
    """Change in security verdict between two assessment runs for a single scenario."""

    scenario_id: str
    title: str
    baseline_verdict: Verdict | None
    current_verdict: Verdict | None
    regression_type: RegressionType
    message: str


@dataclass
class ComparisonReport:
    """Comparison between a baseline assessment and a current assessment run."""

    baseline_id: str
    current_id: str
    deltas: list[ScenarioDelta] = field(default_factory=list)

    @property
    def has_security_regressions(self) -> bool:
        """Return True if any security boundary regression (PASS -> FAIL) occurred."""
        return any(
            d.regression_type == RegressionType.SECURITY_REGRESSION for d in self.deltas
        )

    @property
    def regression_count(self) -> int:
        """Count of severe security regressions."""
        return sum(
            1 for d in self.deltas if d.regression_type == RegressionType.SECURITY_REGRESSION
        )

    @property
    def degradation_count(self) -> int:
        """Count of inconclusive degradations."""
        return sum(
            1 for d in self.deltas if d.regression_type in {RegressionType.DEGRADATION, RegressionType.FAILURE_DEGRADATION}
        )

    @property
    def improvement_count(self) -> int:
        """Count of improvements (previously failing boundaries now holding)."""
        return sum(
            1 for d in self.deltas if d.regression_type == RegressionType.IMPROVEMENT
        )


def compare_assessments(
    baseline: AssessmentReport,
    current: AssessmentReport,
) -> ComparisonReport:
    """Compare two assessment runs and detect security regressions or improvements."""
    baseline_map = {res.scenario_id: res for res in baseline.results}
    current_map = {res.scenario_id: res for res in current.results}

    all_scenario_ids = sorted(set(baseline_map.keys()) | set(current_map.keys()))
    deltas: list[ScenarioDelta] = []

    for sid in all_scenario_ids:
        b_res = baseline_map.get(sid)
        c_res = current_map.get(sid)

        if b_res is None and c_res is not None:
            deltas.append(
                ScenarioDelta(
                    scenario_id=sid,
                    title=c_res.title,
                    baseline_verdict=None,
                    current_verdict=c_res.verdict,
                    regression_type=RegressionType.NEW_SCENARIO,
                    message=f"New scenario added with verdict {c_res.verdict.value}.",
                )
            )
        elif b_res is not None and c_res is None:
            deltas.append(
                ScenarioDelta(
                    scenario_id=sid,
                    title=b_res.title,
                    baseline_verdict=b_res.verdict,
                    current_verdict=None,
                    regression_type=RegressionType.REMOVED_SCENARIO,
                    message=f"Scenario removed from current run (was {b_res.verdict.value}).",
                )
            )
        elif b_res is not None and c_res is not None:
            b_v = b_res.verdict
            c_v = c_res.verdict

            if b_v == c_v:
                reg_type = RegressionType.UNCHANGED
                msg = f"Verdict unchanged ({c_v.value})."
            elif b_v == Verdict.PASS and c_v == Verdict.FAIL:
                reg_type = RegressionType.SECURITY_REGRESSION
                msg = f"SECURITY REGRESSION: Boundary previously held (PASS), now breached (FAIL): {c_res.reason}"
            elif b_v == Verdict.PASS and c_v == Verdict.INCONCLUSIVE:
                reg_type = RegressionType.DEGRADATION
                msg = f"Boundary test degraded from PASS to INCONCLUSIVE: {c_res.reason}"
            elif b_v == Verdict.INCONCLUSIVE and c_v == Verdict.FAIL:
                reg_type = RegressionType.FAILURE_DEGRADATION
                msg = f"Boundary changed from INCONCLUSIVE to FAIL: {c_res.reason}"
            elif c_v == Verdict.PASS:
                reg_type = RegressionType.IMPROVEMENT
                msg = f"Security improved: previous {b_v.value} now PASS."
            else:
                reg_type = RegressionType.UNCHANGED
                msg = f"Verdict shifted from {b_v.value} to {c_v.value}."

            deltas.append(
                ScenarioDelta(
                    scenario_id=sid,
                    title=c_res.title,
                    baseline_verdict=b_v,
                    current_verdict=c_v,
                    regression_type=reg_type,
                    message=msg,
                )
            )

    return ComparisonReport(
        baseline_id=baseline.assessment_id,
        current_id=current.assessment_id,
        deltas=deltas,
    )


__all__ = [
    "ComparisonReport",
    "RegressionType",
    "ScenarioDelta",
    "compare_assessments",
]
