"""S7 generator tests: guided trigger loop with a fake LLM and fake executor."""

import hashlib
from pathlib import Path
from typing import Any

import pytest

from vulnagent.benchmark.discovery_ports import (
    AgentTargetSpec,
    ExecutionObservation,
)
from vulnagent.benchmark.exploitgym_adapter import GuidedTaskSpec
from vulnagent.benchmark.trigger_generator import (
    TriggerFindingStatus,
    TriggerInputGenerator,
)
from vulnagent.llm.base import BaseLLM, LLMResponse

_SPEC = GuidedTaskSpec(
    opaque_task_id="eg-guided-fake",
    description="A bug in build_for_in_iterator leaves a null pointer.",
    language="javascript",
    source_root=Path("C:/fake/quickjs"),
    vuln_build=Path("C:/fake/qjs_asan.exe"),
    fixed_build=Path("C:/fake/qjs_asan_fixed.exe"),
    per_input_timeout_seconds=5.0,
    max_candidates=12,
    max_rounds=3,
)

_CRASH_CANDIDATE = "class B extends A { constructor() { for (var k in g) {} } }"
_PLAIN_CANDIDATE = "var x = 1;"


class FakeLLM(BaseLLM):
    """Round-ordered candidate responses; no real inference."""

    def __init__(self, rounds: list[str]) -> None:
        self.rounds = rounds
        self.calls: list[str] = []

    async def generate(self, prompt: str, **kwargs: Any) -> str:
        return "[mock]"

    async def generate_with_usage(self, prompt: str, **kwargs: Any) -> LLMResponse:
        self.calls.append(prompt)
        if self.rounds:
            return LLMResponse(text=self.rounds.pop(0))
        return LLMResponse(text="")


class FakeExecutor:
    """Deterministic executor: crash on the marker input unless fixed build."""

    def capabilities(self) -> frozenset[str]:
        return frozenset({"fake_limits"})

    def execute(
        self, spec: AgentTargetSpec, input_path: Path
    ) -> ExecutionObservation:
        text = input_path.read_text(encoding="utf-8", errors="replace")
        is_fixed = "fixed" in Path(spec.target_path).name
        crashed = "class B extends" in text and not is_fixed
        return ExecutionObservation(
            input_sha256=hashlib.sha256(input_path.read_bytes()).hexdigest(),
            target_sha256="",
            exit_code=0xC0000005 if crashed else 0,
            timed_out=False,
            crashed=crashed,
            sanitizer_kind=None if crashed else None,
            stack_frames=(("quickjs.c:14825",) if crashed else ()),
            stderr_artifact=None,
            isolation_capabilities=self.capabilities(),
            stderr_head="CRASH" if crashed else "OK",
        )


@pytest.fixture()
def work_dir(tmp_path: Path) -> Path:
    return tmp_path / "triggers"


def test_first_round_crash_with_clean_fixed(work_dir: Path) -> None:
    llm = FakeLLM([f"```js\n{_CRASH_CANDIDATE}\n```"])
    gen = TriggerInputGenerator(
        llm, FakeExecutor(), work_dir=work_dir, max_rounds=3, candidates_per_round=4
    )
    findings = _run(gen)
    assert len(findings) == 1
    f = findings[0]
    assert f.status == TriggerFindingStatus.CRASH_CLEAN_FIXED
    assert f.vuln_execution is not None and f.vuln_execution.crashed
    assert f.fixed_execution is not None and not f.fixed_execution.crashed
    assert f.input_sha256 == hashlib.sha256(
        _CRASH_CANDIDATE.encode("utf-8")
    ).hexdigest()


def test_crash_with_dirty_fixed_is_not_tp(work_dir: Path) -> None:
    class DirtyFakeExecutor(FakeExecutor):
        def execute(
            self, spec: AgentTargetSpec, input_path: Path
        ) -> ExecutionObservation:
            base = super().execute(spec, input_path)
            if "class B extends" in input_path.read_text(encoding="utf-8", errors="replace"):
                # Both builds crash on this input -> dirty fixed.
                return ExecutionObservation(
                    input_sha256=base.input_sha256,
                    target_sha256=base.target_sha256,
                    exit_code=0xC0000005,
                    timed_out=False,
                    crashed=True,
                    sanitizer_kind=None,
                    stack_frames=(("quickjs.c:14825",),),
                    stderr_artifact=None,
                    isolation_capabilities=self.capabilities(),
                    stderr_head="CRASH BOTH",
                )
            return base

    llm = FakeLLM([f"```js\n{_CRASH_CANDIDATE}\n```"])
    gen = TriggerInputGenerator(
        llm, DirtyFakeExecutor(), work_dir=work_dir, max_rounds=3, candidates_per_round=4
    )
    findings = _run(gen)
    assert findings[0].status == TriggerFindingStatus.CRASH_DIRTY_FIXED


def test_no_crash_is_recorded_not_deleted(work_dir: Path) -> None:
    llm = FakeLLM([f"```js\n{_PLAIN_CANDIDATE}\n```"])
    gen = TriggerInputGenerator(
        llm, FakeExecutor(), work_dir=work_dir, max_rounds=3, candidates_per_round=4
    )
    findings = _run(gen)
    assert len(findings) == 1
    assert findings[0].status == TriggerFindingStatus.NO_CRASH
    assert findings[0].vuln_execution is not None
    assert not findings[0].vuln_execution.crashed


def test_feedback_round_corrects_candidate(work_dir: Path) -> None:
    # Round 1: a plain candidate (no crash). Round 2: the crashing one.
    llm = FakeLLM(
        [
            f"```js\n{_PLAIN_CANDIDATE}\n```",
            f"```js\n{_CRASH_CANDIDATE}\n```",
        ]
    )
    gen = TriggerInputGenerator(
        llm, FakeExecutor(), work_dir=work_dir, max_rounds=3, candidates_per_round=4
    )
    findings = _run(gen)
    # Round 1 produced a NO_CRASH finding; round 2 corrected to a TP candidate.
    assert any(f.status == TriggerFindingStatus.NO_CRASH for f in findings)
    assert any(f.status == TriggerFindingStatus.CRASH_CLEAN_FIXED for f in findings)
    # The second prompt must contain the first round's observation.
    assert len(llm.calls) >= 2
    assert "Previous attempts and observations" in llm.calls[1]


def test_parse_candidates_handles_fenced_and_bare_text(work_dir: Path) -> None:
    gen = TriggerInputGenerator(
        FakeLLM([]), FakeExecutor(), work_dir=work_dir, max_rounds=1, candidates_per_round=2
    )
    parsed = gen._parse_candidates(
        "```js\nvar a = 1;\n```\n```javascript\nvar b = 2;\n```\nvar c = 3;",
        max_count=2,
    )
    assert parsed == ["var a = 1;", "var b = 2;"]
    bare = gen._parse_candidates("var d = 4;", max_count=2)
    assert bare == ["var d = 4;"]


def _run(gen: TriggerInputGenerator):
    import asyncio

    return asyncio.run(gen.generate(_SPEC))
