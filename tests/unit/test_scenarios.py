from observatory.evidence.models import Verdict
from observatory.scenarios import get_default_scenarios, get_scenario_by_id


def test_default_scenarios_have_required_metadata_and_threat_models():
    scenarios = get_default_scenarios()
    assert len(scenarios) == 9

    for s in scenarios:
        assert s.scenario_id
        assert s.title
        assert s.description
        assert s.category in {"filesystem", "network", "process"}
        assert s.threat, f"Scenario {s.scenario_id} missing threat model"
        assert s.expected_behavior, f"Scenario {s.scenario_id} missing expected behavior"
        assert s.expected_verdict == Verdict.PASS
        assert s.source.strip()


def test_get_scenario_by_id():
    s = get_scenario_by_id("fs-002")
    assert s is not None
    assert s.title == "Tmpfs No-Execution Boundary"
    assert s.category == "filesystem"

    assert get_scenario_by_id("non-existent") is None
