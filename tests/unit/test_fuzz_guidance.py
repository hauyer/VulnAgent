"""Risk-guided mutation planning stays deterministic and non-exploitative."""

from vulnagent.fuzz.guidance import RiskGuidedMutationPlanner


def test_guidance_is_deterministic_bounded_and_cwe_aware() -> None:
    planner = RiskGuidedMutationPlanner()
    hints = [{"cwe_id": "CWE-89"}, {"vulnerability_type": "path_traversal"}]

    first = planner.generate(b"seed", hints, count=5)
    second = planner.generate(b"seed", hints, count=5)

    assert first == second
    assert len(first) == 5
    assert all(len(item.data) <= 4096 for item in first)
    assert {item.risk_type for item in first} <= {
        "sql_injection",
        "path_traversal",
    }
    assert all(item.strategy.startswith("risk_guided:") for item in first)


def test_unknown_hints_do_not_generate_payloads() -> None:
    planner = RiskGuidedMutationPlanner()

    assert planner.generate(
        b"seed",
        [{"vulnerability_type": "unknown", "cwe_id": "CWE-000"}],
        count=4,
    ) == []
