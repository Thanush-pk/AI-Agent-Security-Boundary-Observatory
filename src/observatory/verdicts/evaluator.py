import json
import uuid
from typing import Any

from observatory.evidence.models import (
    EvidenceRecord,
    EvidenceSource,
    ScenarioResult,
    Verdict,
)
from observatory.runtime.docker_runtime import ExecutionResult


def parse_observation_payload(output: str) -> dict[str, Any] | None:
    """Extract structured JSON payload emitted by a scenario probe."""
    for line in reversed(output.strip().splitlines()):
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            try:
                data = json.loads(line)
                if isinstance(data, dict):
                    return data
            except json.JSONDecodeError:
                continue
    return None


def evaluate_boundary_execution(
    scenario_id: str,
    title: str,
    execution: ExecutionResult,
) -> ScenarioResult:
    """Evaluate container execution output and produce a ScenarioResult with evidence."""
    evidence_list: list[EvidenceRecord] = []

    # Case 1: Execution timed out
    if execution.timed_out:
        evidence_list.append(
            EvidenceRecord(
                evidence_id=f"ev-{uuid.uuid4().hex[:8]}",
                source=EvidenceSource.SYSTEM_ERROR,
                description="Container execution timed out before completion.",
                data={"timed_out": True, "output": execution.output},
            )
        )
        return ScenarioResult(
            scenario_id=scenario_id,
            title=title,
            verdict=Verdict.INCONCLUSIVE,
            reason="Execution timed out before the boundary test completed.",
            evidence=evidence_list,
        )

    # Runtime log evidence
    evidence_list.append(
        EvidenceRecord(
            evidence_id=f"ev-{uuid.uuid4().hex[:8]}",
            source=EvidenceSource.RUNTIME_LOG,
            description="Captured container execution output and status.",
            data={
                "exit_code": execution.exit_code,
                "output": execution.output,
            },
        )
    )

    payload = parse_observation_payload(execution.output)

    if payload is not None and "boundary_held" in payload:
        held = payload.get("boundary_held")
        detail = payload.get("detail", "No observation detail provided.")

        evidence_list.append(
            EvidenceRecord(
                evidence_id=f"ev-{uuid.uuid4().hex[:8]}",
                source=EvidenceSource.TEST_OBSERVATION,
                description=detail,
                data=payload,
            )
        )

        if held is True:
            return ScenarioResult(
                scenario_id=scenario_id,
                title=title,
                verdict=Verdict.PASS,
                reason=detail,
                evidence=evidence_list,
            )
        elif held is False:
            return ScenarioResult(
                scenario_id=scenario_id,
                title=title,
                verdict=Verdict.FAIL,
                reason=f"Security boundary violated: {detail}",
                evidence=evidence_list,
            )
        else:
            return ScenarioResult(
                scenario_id=scenario_id,
                title=title,
                verdict=Verdict.INCONCLUSIVE,
                reason=f"Probe reported inconclusive outcome: {detail}",
                evidence=evidence_list,
            )

    # If non-zero exit code without structured payload
    if execution.exit_code != 0:
        evidence_list.append(
            EvidenceRecord(
                evidence_id=f"ev-{uuid.uuid4().hex[:8]}",
                source=EvidenceSource.SYSTEM_ERROR,
                description=f"Process exited abnormally with code {execution.exit_code}.",
                data={"exit_code": execution.exit_code, "output": execution.output},
            )
        )
        return ScenarioResult(
            scenario_id=scenario_id,
            title=title,
            verdict=Verdict.INCONCLUSIVE,
            reason=f"Process failed with exit code {execution.exit_code} without structured evidence.",
            evidence=evidence_list,
        )

    # Clean exit code 0 but no recognizable observation payload
    return ScenarioResult(
        scenario_id=scenario_id,
        title=title,
        verdict=Verdict.INCONCLUSIVE,
        reason="Execution finished with exit code 0 but no boundary observation payload was found.",
        evidence=evidence_list,
    )
