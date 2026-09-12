"""Validated loader for the defensive software-code rule library."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

import yaml


DEFAULT_RULE_LIBRARY = (
    Path(__file__).resolve().parents[5] / "configs" / "source_audit_rules.yaml"
)
_RULE_ID = re.compile(r"^VA-NATIVE-[A-Z]+-[0-9]{3}$")
_SEVERITIES = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"})
_LANGUAGES = frozenset({"c", "cpp", "go"})
_REQUIRED_FORBIDDEN = frozenset({"poc", "exploit", "attack_payload", "bypass_steps"})


class RuleLibraryError(ValueError):
    """Raised when a rule file violates the bounded defensive schema."""


@dataclass(frozen=True, slots=True)
class SoftwareCodeRule:
    """One provider-neutral rule definition loaded from YAML."""

    rule_id: str
    name: str
    description: str
    vulnerability_type: str
    cwe_id: str
    languages: tuple[str, ...]
    match: Mapping[str, Any]
    severity: str
    confidence: float
    remediation_summary: str
    remediation_actions: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class SoftwareCodeRuleLibrary:
    """Immutable validated rule collection."""

    schema_version: str
    library_id: str
    description: str
    rules: tuple[SoftwareCodeRule, ...]

    def by_id(self, rule_id: str) -> SoftwareCodeRule | None:
        return next((rule for rule in self.rules if rule.rule_id == rule_id), None)


def load_rule_library(path: Path = DEFAULT_RULE_LIBRARY) -> SoftwareCodeRuleLibrary:
    """Load and validate a local YAML rule library without executing content."""

    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise RuleLibraryError(f"unable to load rule library: {path}") from exc
    if not isinstance(raw, Mapping):
        raise RuleLibraryError("rule library root must be a mapping")
    if raw.get("schema_version") != "1.0":
        raise RuleLibraryError("unsupported rule-library schema version")
    safety = raw.get("safety")
    if not isinstance(safety, Mapping) or safety.get("defensive_only") is not True:
        raise RuleLibraryError("rule library must declare defensive_only=true")
    forbidden = {str(item) for item in safety.get("forbidden_outputs", [])}
    if not _REQUIRED_FORBIDDEN.issubset(forbidden):
        raise RuleLibraryError("rule library must forbid offensive output classes")

    raw_rules = raw.get("rules")
    if not isinstance(raw_rules, list) or not raw_rules:
        raise RuleLibraryError("rule library must contain at least one rule")
    rules: list[SoftwareCodeRule] = []
    seen: set[str] = set()
    for index, item in enumerate(raw_rules):
        if not isinstance(item, Mapping):
            raise RuleLibraryError(f"rule {index} must be a mapping")
        rule_id = str(item.get("rule_id") or "")
        if not _RULE_ID.fullmatch(rule_id) or rule_id in seen:
            raise RuleLibraryError(f"invalid or duplicate rule_id: {rule_id!r}")
        seen.add(rule_id)
        languages = tuple(str(value) for value in item.get("languages", []))
        if not languages or not set(languages).issubset(_LANGUAGES):
            raise RuleLibraryError(f"invalid languages for {rule_id}")
        severity = str(item.get("severity") or "")
        if severity not in _SEVERITIES:
            raise RuleLibraryError(f"invalid severity for {rule_id}")
        try:
            confidence = float(item.get("confidence"))
        except (TypeError, ValueError) as exc:
            raise RuleLibraryError(f"invalid confidence for {rule_id}") from exc
        if not 0.0 <= confidence <= 1.0:
            raise RuleLibraryError(f"confidence out of range for {rule_id}")
        match = item.get("match")
        remediation = item.get("remediation")
        if not isinstance(match, Mapping) or not isinstance(remediation, Mapping):
            raise RuleLibraryError(f"missing match/remediation for {rule_id}")
        actions = remediation.get("actions")
        if not isinstance(actions, list) or not actions:
            raise RuleLibraryError(f"missing remediation actions for {rule_id}")
        rules.append(
            SoftwareCodeRule(
                rule_id=rule_id,
                name=str(item.get("name") or rule_id),
                description=str(item.get("description") or ""),
                vulnerability_type=str(item.get("vulnerability_type") or ""),
                cwe_id=str(item.get("cwe_id") or ""),
                languages=languages,
                match=dict(match),
                severity=severity,
                confidence=confidence,
                remediation_summary=str(remediation.get("summary") or ""),
                remediation_actions=tuple(str(action) for action in actions),
            )
        )
    return SoftwareCodeRuleLibrary(
        schema_version="1.0",
        library_id=str(raw.get("library_id") or ""),
        description=str(raw.get("description") or ""),
        rules=tuple(rules),
    )


__all__ = [
    "DEFAULT_RULE_LIBRARY",
    "RuleLibraryError",
    "SoftwareCodeRule",
    "SoftwareCodeRuleLibrary",
    "load_rule_library",
]
