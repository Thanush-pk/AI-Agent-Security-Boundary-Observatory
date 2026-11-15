
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Verdict(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    INCONCLUSIVE = "INCONCLUSIVE"


class EvidenceSource(str, Enum):
    CONTAINER_INSPECTION = "container_inspection"
    TEST_OBSERVATION = "test_observation"
    RUNTIME_LOG = "runtime_log"
    SYSTEM_ERROR = "system_error"


class EvidenceRecord(BaseModel):
    """A record of an observed fact supporting an assessment."""

    model_config = ConfigDict(extra="forbid")

    evidence_id: str
    source: EvidenceSource
    observed_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC)
    )
    description: str
    data: dict[str, Any] = Field(default_factory=dict)


class ScenarioResult(BaseModel):
    """Outcome of one controlled security scenario."""

    model_config = ConfigDict(extra="forbid")

    scenario_id: str
    title: str
    verdict: Verdict
    reason: str
    evidence: list[EvidenceRecord] = Field(default_factory=list)


class AssessmentReport(BaseModel):
    """Portable report for a complete assessment run."""

    model_config = ConfigDict(extra="forbid")

    assessment_id: str
    runtime: str
    started_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC)
    )
    results: list[ScenarioResult] = Field(default_factory=list)

    @property
    def summary(self) -> dict[str, int]:
        return {
            verdict.value.lower(): sum(
                result.verdict == verdict for result in self.results
            )
            for verdict in Verdict
        }
