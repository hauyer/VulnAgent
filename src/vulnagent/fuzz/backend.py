"""V0.8 Dynamic Confirmation: fuzz backends.

``FuzzBackend`` is the adapter boundary for external fuzzers (libFuzzer,
AFL++) and the self-authored ``PythonFuzzBackend`` which mutates seeds and
executes the generated harness in isolated subprocesses, classifying crashes
through :class:`CrashTriage`.  The backend is the dynamic counterpart of the
V0.5+ analyzer adapters: never raw tool invocation from business code.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from vulnagent.contracts import Evidence, VulnerabilityCandidate
from vulnagent.fuzz.corpus import CorpusManager, SeedGenerator
from vulnagent.fuzz.executor import ControlledExecutor
from vulnagent.fuzz.harness import CoverageTracker, HarnessGenerator
from vulnagent.fuzz.mutation import MutationEngine
from vulnagent.fuzz.triage import CrashRecord, CrashTriage

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class FuzzOutcome:
    """Result of one fuzz campaign."""

    executed: bool
    crashes: list[CrashRecord] = field(default_factory=list)
    executions: int = 0
    coverage: dict[str, int] = field(default_factory=dict)
    evidence: list[Evidence] = field(default_factory=list)
    error: str | None = None


class FuzzBackend(Protocol):
    """Adapter boundary for fuzz execution engines."""

    def run_campaign(
        self,
        *,
        target: Path,
        candidate: VulnerabilityCandidate,
        run_id: str,
        iterations: int,
        timeout_seconds: float,
        session_id: str,
        work_dir: Path,
    ) -> FuzzOutcome: ...


class PythonFuzzBackend:
    """Self-authored Python fuzz backend: mutation + sandboxed execution."""

    def __init__(
        self,
        *,
        seed: int = 0,
        executor_timeout: float = 1.0,
        max_output_bytes: int = 64 * 1024,
    ) -> None:
        self.mutator = MutationEngine(seed=seed)
        self.executor = ControlledExecutor(
            timeout_seconds=executor_timeout,
            max_output_bytes=max_output_bytes,
        )
        self.triage = CrashTriage()
        self.seed_generator = SeedGenerator()
        self.corpus = CorpusManager()
        self.harness_generator = HarnessGenerator()
        self.coverage = CoverageTracker()

    def run_campaign(
        self,
        *,
        target: Path,
        candidate: VulnerabilityCandidate,
        run_id: str,
        iterations: int,
        timeout_seconds: float,
        session_id: str,
        work_dir: Path,
    ) -> FuzzOutcome:
        harness_dir = work_dir / "harness"
        corpus_dir = work_dir / "corpus"
        harness_dir.mkdir(parents=True, exist_ok=True)
        corpus_dir.mkdir(parents=True, exist_ok=True)

        # 1. Seeds from the candidate shape.
        seeds = self.seed_generator.generate(candidate)
        self.corpus.add_many(seeds)
        self.corpus.save(corpus_dir)

        crashes: list[CrashRecord] = []
        evidence: list[Evidence] = []
        crash_count = 0
        executed = 0

        # 2. Mutation + execution loop (bounded iterations).
        for iteration in range(max(1, iterations)):
            batch: list[bytes] = list(self.corpus.inputs)
            for seed_bytes in self.corpus.inputs:
                batch.extend(self.mutator.mutate(seed_bytes, count=3))
            for input_bytes in batch[:8]:
                input_file = work_dir / "input" / f"in-{iteration}"
                input_file.parent.mkdir(parents=True, exist_ok=True)
                input_file.write_bytes(input_bytes)
                harness = self.harness_generator.generate(
                    target, input_file, harness_dir / "harness.py"
                )
                execution = self.executor.execute(harness, input_bytes, work_dir)
                executed += 1
                record = self.triage.classify(
                    execution=execution,
                    input_bytes=input_bytes,
                    task_id=candidate.task_id,
                    target_id=candidate.target_id,
                    run_id=run_id,
                    index=crash_count,
                )
                self.coverage.record(
                    timed_out=execution.timed_out,
                    returncode=execution.returncode,
                    exception=bool(record and record.kind == "exception"),
                )
                if record is not None:
                    crashes.append(record)
                    evidence.extend(record.to_evidence(session_id, run_id))
                    crash_count += 1
                self.corpus.add(input_bytes)
                if crash_count >= 1:
                    break
            if crash_count >= 1:
                break

        return FuzzOutcome(
            executed=True,
            crashes=crashes,
            executions=executed,
            coverage=self.coverage.report(),
            evidence=evidence,
        )
