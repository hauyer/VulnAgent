"""Defensive YAML rule-library validation."""

from pathlib import Path

import pytest

from vulnagent.analyzers.source.audit.rule_library import (
    RuleLibraryError,
    load_rule_library,
)


def test_default_rule_library_is_valid_and_defensive() -> None:
    library = load_rule_library()

    assert library.schema_version == "1.0"
    assert len(library.rules) >= 8
    assert library.by_id("VA-NATIVE-MEM-001") is not None
    assert {rule.vulnerability_type for rule in library.rules} >= {
        "buffer_overflow",
        "integer_overflow",
        "array_out_of_bounds",
        "input_validation_missing",
        "configuration_authorization_missing",
        "null_pointer_dereference",
        "resource_leak",
        "interface_access_control_missing",
    }
    assert all(rule.remediation_actions for rule in library.rules)


def test_loader_rejects_library_without_defensive_boundary(tmp_path: Path) -> None:
    path = tmp_path / "unsafe.yaml"
    path.write_text(
        "schema_version: '1.0'\nlibrary_id: bad\nsafety:\n  defensive_only: false\n  forbidden_outputs: []\nrules: []\n",
        encoding="utf-8",
    )

    with pytest.raises(RuleLibraryError, match="defensive_only"):
        load_rule_library(path)
