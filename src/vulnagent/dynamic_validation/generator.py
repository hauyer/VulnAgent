"""Harmless boundary-case generator for documented local API fields."""

from __future__ import annotations

from collections.abc import Sequence
from copy import deepcopy
from typing import Any

from .models import CaseKind, InputFieldSpec, RobustnessCase, SandboxPolicy


class BoundaryCaseGenerator:
    """Generate bounded null/empty/limit/type cases without attack strings."""

    def generate(
        self,
        base_request: dict[str, object],
        fields: Sequence[InputFieldSpec],
        policy: SandboxPolicy,
    ) -> list[RobustnessCase]:
        cases: list[RobustnessCase] = []
        for field in fields:
            variants = self._variants(field, policy)
            for kind, value, summary in variants:
                body: dict[str, Any] = deepcopy(base_request)
                if not self._replace(body, field.path, value):
                    continue
                cases.append(
                    RobustnessCase(
                        case_id=f"case-{len(cases) + 1:03d}",
                        kind=kind,
                        field_path=field.path,
                        request_body=body,
                        input_summary=summary,
                    )
                )
                if len(cases) >= policy.case_limit:
                    return cases
        return cases

    @staticmethod
    def _replace(root: dict[str, Any], path: tuple[str, ...], value: Any) -> bool:
        if not path:
            return False
        current: dict[str, Any] = root
        for part in path[:-1]:
            nested = current.get(part)
            if not isinstance(nested, dict):
                return False
            current = nested
        current[path[-1]] = value
        return True

    @staticmethod
    def _variants(
        field: InputFieldSpec,
        policy: SandboxPolicy,
    ) -> list[tuple[CaseKind, Any, dict[str, Any]]]:
        variants: list[tuple[CaseKind, Any, dict[str, Any]]] = []
        if field.nullable:
            variants.append((CaseKind.NULL_VALUE, None, {"value_class": "null"}))
        if field.value_type == "string":
            variants.extend(
                [
                    (CaseKind.EMPTY_TEXT, "", {"value_class": "empty_text", "length": 0}),
                    (
                        CaseKind.OVERSIZED_TEXT,
                        "A" * min(
                            policy.max_text_length,
                            max(256, (field.max_length or 255) + 1),
                        ),
                        {
                            "value_class": "over_documented_length",
                            "length": min(
                                policy.max_text_length,
                                max(256, (field.max_length or 255) + 1),
                            ),
                        },
                    ),
                    (CaseKind.MALFORMED_TYPE, 0, {"value_class": "wrong_primitive_type"}),
                ]
            )
        elif field.value_type in {"integer", "number"}:
            boundaries = []
            if field.minimum is not None:
                boundaries.extend([field.minimum, field.minimum - 1])
            if field.maximum is not None:
                boundaries.extend([field.maximum, field.maximum + 1])
            if not boundaries:
                boundaries = [-1, 0]
            variants.extend(
                (
                    CaseKind.BOUNDARY_NUMBER,
                    value,
                    {"value_class": "numeric_boundary", "relation": f"variant_{index + 1}"},
                )
                for index, value in enumerate(boundaries[:4])
            )
            variants.append(
                (CaseKind.MALFORMED_TYPE, "", {"value_class": "wrong_primitive_type"})
            )
        else:
            variants.append(
                (CaseKind.MALFORMED_TYPE, None, {"value_class": "wrong_or_null_type"})
            )
        return variants
