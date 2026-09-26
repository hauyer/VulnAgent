"""L7: guided variant hypothesis tests (review/variant)."""

from __future__ import annotations

from pathlib import Path

from vulnagent.review.variant import (
    VariantHypothesisBuilder,
    VariantPatternKind,
    describe_pattern,
)


class TestVariantHypothesisBuilder:
    def test_never_contains_cve_labels(self, tmp_path: Path) -> None:
        builder = VariantHypothesisBuilder()
        _write_c_project(tmp_path)
        for hypothesis in builder.build(tmp_path):
            payload = str(hypothesis.digest()).upper()
            assert "CVE-" not in payload
            assert hypothesis.track == "guided_variant_search"
            assert hypothesis.based_on_known_pattern is True

    def test_finds_sites_in_real_demo_source(self, tmp_path: Path) -> None:
        builder = VariantHypothesisBuilder()
        _write_c_project(tmp_path)
        hypotheses = builder.build(tmp_path)
        assert hypotheses
        kinds = {h.pattern_kind for h in hypotheses}
        assert VariantPatternKind.MISSING_NULL_CHECK in kinds
        for hypothesis in hypotheses:
            assert hypothesis.candidate_sites  # sites come from the target itself

    def test_abstract_invariants_described(self) -> None:
        for kind in VariantPatternKind:
            description = describe_pattern(kind)
            assert "invariant" in description
            assert "CVE" not in description

    def test_missing_root_returns_empty(self) -> None:
        builder = VariantHypothesisBuilder()
        assert builder.build(Path("nonexistent-dir-xyz")) == []


def _write_c_project(root: Path) -> None:
    (root / "parse.c").write_text(
        "void parse(const char* p) {\n"
        "  char* tmp = malloc(8);\n"
        "  strcpy(tmp, p);\n"          # unbounded copy site
        "  sscanf(p, \"%s\", tmp);\n"  # unbounded field parse site
        "}\n",
        encoding="utf-8",
    )
