from dataclasses import dataclass
from datetime import datetime
from typing import Any

from observatory.evidence.models import AssessmentReport, Verdict


@dataclass(frozen=True)
class TimelineEvent:
    """An event in the reconstructed assessment or incident timeline."""

    timestamp: datetime
    scenario_id: str
    scenario_title: str
    event_type: str
    verdict: Verdict | None
    description: str
    details: dict[str, Any]


def reconstruct_timeline(report: AssessmentReport) -> list[TimelineEvent]:
    """Reconstruct an ordered chronological timeline of events from an AssessmentReport."""
    events: list[TimelineEvent] = []

    # Assessment started event
    events.append(
        TimelineEvent(
            timestamp=report.started_at,
            scenario_id="ASSESSMENT",
            scenario_title=f"Assessment Run: {report.assessment_id}",
            event_type="assessment_started",
            verdict=None,
            description=f"Assessment {report.assessment_id} initiated against runtime '{report.runtime}'.",
            details={"runtime": report.runtime, "total_scenarios": len(report.results)},
        )
    )

    for result in report.results:
        for evidence in result.evidence:
            events.append(
                TimelineEvent(
                    timestamp=evidence.observed_at,
                    scenario_id=result.scenario_id,
                    scenario_title=result.title,
                    event_type=evidence.source.value,
                    verdict=result.verdict,
                    description=evidence.description,
                    details=evidence.data,
                )
            )

    # Sort all events chronologically by timestamp
    events.sort(key=lambda e: e.timestamp)
    return events


def format_timeline_text(events: list[TimelineEvent]) -> str:
    """Format a list of timeline events into a human-readable text log."""
    lines: list[str] = []
    lines.append("Chronological Incident & Assessment Timeline:")
    lines.append("-" * 78)

    for event in events:
        time_str = event.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + " UTC"
        verdict_str = f"[{event.verdict.value}] " if event.verdict else ""
        lines.append(f"{time_str} | {event.scenario_id:<10} | {event.event_type:<18} | {verdict_str}{event.description}")

    lines.append("-" * 78)
    return "\n".join(lines)


__all__ = ["TimelineEvent", "format_timeline_text", "reconstruct_timeline"]
