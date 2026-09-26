"""L3/L9: target profile + workflow profile tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from vulnagent.intake.models import (
    Authorization,
    DatasetRole,
    IntakeDecision,
    TargetKind,
    TargetManifest,
)
from vulnagent.intake.profile import DefaultTargetProfiler, StudyTrack, TargetProfile
from vulnagent.intake.workflow import (
    WORKFLOW_PROFILES,
    WorkflowProfileName,
    get_workflow_profile,
)


def _manifest(path: str = "targets/foo/foo.c", dynamic: bool = True) -> TargetManifest:
    return TargetManifest(
        sample_id="foo",
        source_name="Foo Project",
        role=DatasetRole.EXPLORATORY,
        revision="abc123",
        target_path=path,
        target_sha256="ab" * 32,
        license_record="MIT",
        target_kind=TargetKind.SOURCE,
        language="c",
        authorization=Authorization(
            static_read=True,
            dynamic_run=dynamic,
        ),
    )


def _accepted(manifest: TargetManifest) -> IntakeDecision:
    return IntakeDecision(
        accepted=True,
        issues=[],
        sample_id=manifest.sample_id,
        normalized_path=manifest.target_path,
        checked_sha256=manifest.target_sha256,
    )


class TestTargetProfile:
    def test_profile_from_accepted_decision(self) -> None:
        manifest = _manifest()
        profile = DefaultTargetProfiler().profile(
            _accepted(manifest),
            manifest,
            track=StudyTrack.EXTERNAL_UNKNOWN,
        )
        assert profile.track is StudyTrack.EXTERNAL_UNKNOWN
        assert profile.opaque_target_id == "opaque-foo"
        assert profile.target_kind == "source"
        assert profile.dynamic_run is True
        assert profile.max_seconds == 300

    def test_rejected_decision_raises(self) -> None:
        manifest = _manifest()
        rejected = IntakeDecision(
            accepted=False,
            issues=["not authorized"],
            sample_id=manifest.sample_id,
            normalized_path=None,
            checked_sha256=None,
        )
        with pytest.raises(ValueError, match="not admitted"):
            DefaultTargetProfiler().profile(rejected, manifest)

    def test_route_subset_includes_fuzz_when_dynamic(self) -> None:
        manifest = _manifest(dynamic=True)
        profile = DefaultTargetProfiler().profile(_accepted(manifest), manifest)
        routes = profile.route_subset()
        assert "fuzz" in routes

    def test_guided_variant_track_allows_code_audit(self) -> None:
        manifest = _manifest()
        profile = DefaultTargetProfiler().profile(
            _accepted(manifest),
            manifest,
            track=StudyTrack.GUIDED_VARIANT,
        )
        assert "code_audit" in profile.route_subset()

    def test_digest_roundtrip(self) -> None:
        manifest = _manifest()
        profile = DefaultTargetProfiler().profile(_accepted(manifest), manifest)
        digest = profile.digest()
        rebuilt = DefaultTargetProfiler().profile_from_digest(digest)
        assert rebuilt.opaque_target_id == profile.opaque_target_id
        assert rebuilt.track is profile.track
        assert rebuilt.max_seconds == profile.max_seconds


class TestWorkflowProfile:
    def test_all_named_profiles_exist(self) -> None:
        for name in WorkflowProfileName:
            assert name in WORKFLOW_PROFILES
            assert get_workflow_profile(name).name is name

    def test_external_exploration_has_bounded_steps_and_dynamic(self) -> None:
        profile = get_workflow_profile(WorkflowProfileName.EXTERNAL_EXPLORATION)
        assert profile.allow_dynamic is True
        assert profile.max_agent_steps >= 8
        assert profile.study_track is StudyTrack.EXTERNAL_UNKNOWN

    def test_source_audit_is_static_only(self) -> None:
        profile = get_workflow_profile(WorkflowProfileName.SOURCE_AUDIT)
        assert profile.allow_dynamic is False
        assert profile.allow_guided_hints is False

    def test_unknown_name_raises(self) -> None:
        with pytest.raises(ValueError):
            get_workflow_profile("no_such_profile")
