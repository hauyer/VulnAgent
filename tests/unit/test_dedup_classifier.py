"""S5 dedup classifier (roadmap work-package C step 4) unit tests."""

from __future__ import annotations

from vulnagent.review.triage import (
    DedupClass,
    DedupClassifier,
    PublicAdvisory,
)


def _meta(title: str, description: str, root_cause: str = "") -> dict:
    return {"title": title, "description": description, "root_cause": root_cause}


class TestDedupClassifier:
    def test_known_duplicate_on_fingerprint_match(self) -> None:
        clf = DedupClassifier(
            [
                PublicAdvisory(
                    cve_id="CVE-2026-43623",
                    root_cause_fingerprint="raw_to_header",
                    affected_version="0.1.0",
                    fixed_revision=None,
                    source="nvd",
                )
            ]
        )
        res = clf.classify(
            "vuln-mt-0001",
            _meta("microtar strcpy overflow", "raw_to_header uses strcpy on fixed-width fields"),
            reproducible=True,
            verification_status="CONFIRMED",
        )
        assert res.dedup_class == DedupClass.KNOWN_DUPLICATE
        assert res.matched[0].cve_id == "CVE-2026-43623"

    def test_false_positive_when_not_reproducible(self) -> None:
        clf = DedupClassifier()
        res = clf.classify(
            "cand-x",
            _meta("crash candidate", "heap overflow"),
            reproducible=False,
            verification_status="UNCERTAIN",
        )
        assert res.dedup_class == DedupClass.FALSE_POSITIVE
        assert any("replay" in r for r in res.reasons)

    def test_false_positive_when_verification_rejects(self) -> None:
        clf = DedupClassifier()
        res = clf.classify(
            "cand-y",
            _meta("candidate", "crash"),
            reproducible=True,
            verification_status="REJECTED",
        )
        assert res.dedup_class == DedupClass.FALSE_POSITIVE
        assert any("verification" in r for r in res.reasons)

    def test_needs_more_evidence_without_human_review(self) -> None:
        clf = DedupClassifier()
        res = clf.classify(
            "vuln-wasm3-s001",
            _meta("wasm3 null deref", "malformed module _start NULL dereference"),
            reproducible=True,
            verification_status="CONFIRMED",
            human_reviewed=False,
        )
        assert res.dedup_class == DedupClass.NEEDS_MORE_EVIDENCE
        assert any("human" in r for r in res.reasons)

    def test_novelty_unknown_only_after_human_review(self) -> None:
        clf = DedupClassifier()
        res = clf.classify(
            "cand-z",
            _meta("candidate", "novel crash"),
            reproducible=True,
            verification_status="CONFIRMED",
            human_reviewed=True,
        )
        assert res.dedup_class == DedupClass.NOVELTY_UNKNOWN

    def test_real_microtar_case_classifies_duplicate(self) -> None:
        clf = DedupClassifier(
            [
                PublicAdvisory(
                    cve_id="CVE-2026-55738",
                    root_cause_fingerprint="raw_to_header",
                    affected_version="0.1.0",
                    fixed_revision=None,
                    source="cve.org",
                )
            ]
        )
        res = clf.classify(
            "vuln-mt-0001",
            _meta(
                "microtar raw_to_header missing NUL-termination handling",
                "sscanf/strcpy in raw_to_header on fixed-width ustar fields",
                "raw_to_header strcpy OOB read",
            ),
            reproducible=True,
            verification_status="CONFIRMED",
        )
        assert res.dedup_class == DedupClass.KNOWN_DUPLICATE

    def test_real_wasm3_surface_case_stays_conservative(self) -> None:
        clf = DedupClassifier()
        res = clf.classify(
            "vuln-wasm3-s001",
            _meta(
                "wasm3 NULL function reference dereference",
                "malformed export section module; calling _start crashes at NULL+8",
            ),
            reproducible=True,
            verification_status="CONFIRMED",
            human_reviewed=False,
        )
        assert res.dedup_class == DedupClass.NEEDS_MORE_EVIDENCE
