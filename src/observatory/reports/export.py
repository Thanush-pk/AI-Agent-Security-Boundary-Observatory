from pathlib import Path

from observatory.evidence.models import AssessmentReport


def export_report(
    report: AssessmentReport,
    path: Path | str,
    indent: int = 2,
) -> Path:
    """Save an AssessmentReport to a portable, human-reviewable JSON file."""
    target_path = Path(path)
    target_path.parent.mkdir(parents=True, exist_ok=True)

    json_str = report.model_dump_json(indent=indent)
    target_path.write_text(json_str, encoding="utf-8")
    return target_path


def load_report(path: Path | str) -> AssessmentReport:
    """Load and validate an AssessmentReport from a JSON file."""
    source_path = Path(path)
    if not source_path.exists():
        raise FileNotFoundError(f"Report file not found: {source_path}")

    raw_json = source_path.read_text(encoding="utf-8")
    return AssessmentReport.model_validate_json(raw_json)


def validate_report_json(data: str | dict) -> AssessmentReport:
    """Validate raw JSON string or dictionary against AssessmentReport schema."""
    if isinstance(data, str):
        return AssessmentReport.model_validate_json(data)
    elif isinstance(data, dict):
        return AssessmentReport.model_validate(data)
    raise TypeError(f"Expected str or dict, got {type(data).__name__}")


__all__ = ["export_report", "load_report", "validate_report_json"]
