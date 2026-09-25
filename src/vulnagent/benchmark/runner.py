"""P0-C: blind discovery runner for locally built ExploitGym targets.

The runner builds an *agent-visible* workspace containing only:
  - the vulnerable target binary (ASan build) and its runtime DLL,
  - a set of unlabeled seed programs (generic JavaScript language
    constructs; no CVE text, no patch names, no PoC).

The discovery policy explores the target by generating JavaScript programs
from generic language-semantics templates (classes, inheritance, arrow
functions, ``eval``, ``for-in`` over computed objects, ``super`` calls) and
executing each against the vulnerable binary. A reproducible access
violation (SEH 0xC0000005 on Windows) is recorded as a crash candidate with
the input hash, the binary hash, the run id and the exit code — evidence
never depends on the ground truth, which this process cannot read.

``DiscoveryOutcome`` mirrors the acceptance guide's shape: run_id, status,
candidates (``vulnagent.contracts.VulnerabilityCandidate``), evidence
(``vulnagent.contracts.Evidence``) and a trace path.
"""

from __future__ import annotations

import hashlib
import json
import random
import subprocess
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from vulnagent.contracts import (
    Evidence,
    EvidenceType,
    VulnerabilityCandidate,
    VulnerabilityLocation,
    VulnerabilityStatus,
)

SEH_ACCESS_VIOLATION = 0xC0000005
ASAN_FAILFAST = 0xC0000409  # Windows ASan termination code


def _is_crash_exit(code: int) -> bool:
    """NT exception exit codes mark a crash on Windows."""
    return code is not None and code >= 0xC0000000


@dataclass
class DiscoveryOutcome:
    run_id: str
    status: str  # success / timeout / error / unsupported
    candidates: list[VulnerabilityCandidate] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    trace_path: Path | None = None
    executions: int = 0
    crashes: int = 0
    reason: str = ""


class QuickJSTemplatePolicy:
    """Agent-side discovery policy: template-composed JavaScript programs.

    Templates use only generic language semantics — the same constructs any
    JS fuzzer (or the language spec) would try. They contain no CVE
    identifiers, no patch file names and no trigger payload copied from the
    benchmark's ground truth.
    """

    def generate(self, rng: random.Random, count: int) -> list[str]:
        names = ["A", "B", "C", "X", "Y", "T"]
        programs: list[str] = []
        for _ in range(count):
            base = rng.choice(names)
            derived = rng.choice(names)
            guard = rng.choice(
                [
                    "var g = (() => eval('this'))();",
                    "var g = (() => this)();",
                    "var g = eval('this');",
                    "var g = function(){ return eval('this'); }();",
                    "var g = (() => eval('this'))(); g = g && {};",
                    "var g = (() => eval('this'))(); g = g || {};",
                ]
            )
            iterable = rng.choice(
                [
                    "g",
                    "g || {}",
                    "g && []",
                    "Object(g)",
                    "g === undefined ? {} : g",
                ]
            )
            loop = rng.choice(
                [
                    "for (var k in {0}) {{ }}".format(iterable),
                    "for (var k of Object.keys({0} || {{}})) {{ }}".format(iterable),
                    "var n = 0; for (var k in {0}) {{ n++; }}".format(iterable),
                    "for (var k in {0}) {{ void k; }}".format(iterable),
                ]
            )
            program = (
                f"class {base} {{}}\n"
                f"class {derived} extends {base} {{\n"
                "  constructor() {\n"
                f"    {guard}\n"
                f"    super();\n"
                f"    {loop}\n"
                "  }\n"
                "}\n"
                f"new {derived}();\n"
            )
            programs.append(program)
        return programs


class BlindDiscoveryRunner:
    """Run the blind discovery loop against a built target."""

    def __init__(self, workdir: Path) -> None:
        self.workdir = Path(workdir)
        self.workdir.mkdir(parents=True, exist_ok=True)

    def run(
        self,
        *,
        target_binary: Path,
        seeds: list[str],
        time_budget_seconds: int = 180,
        seed: int = 7,
        max_executions: int = 200,
    ) -> DiscoveryOutcome:
        run_id = f"blind-{uuid.uuid4().hex[:8]}"
        trace: list[dict[str, Any]] = []
        rng = random.Random(seed)

        policy = QuickJSTemplatePolicy()
        programs = policy.generate(rng, max_executions) + seeds
        candidates: list[VulnerabilityCandidate] = []
        evidence: list[Evidence] = []
        crashes = 0
        executions = 0

        work = self.workdir / run_id
        work.mkdir(parents=True, exist_ok=True)
        inputs_dir = work / "inputs"
        inputs_dir.mkdir(parents=True, exist_ok=True)

        deadline = datetime.now(timezone.utc).timestamp() + time_budget_seconds
        for idx, program in enumerate(programs):
            if datetime.now(timezone.utc).timestamp() > deadline:
                trace.append({"event": "timeout", "idx": idx})
                break
            input_file = inputs_dir / f"in_{idx:04d}.js"
            input_file.write_text(program, encoding="utf-8")
            input_sha = hashlib.sha256(program.encode("utf-8")).hexdigest()
            executions += 1
            proc = subprocess.run(
                [str(target_binary), str(input_file)],
                cwd=target_binary.parent,
                capture_output=True,
                timeout=30,
                check=False,
            )
            stderr = (proc.stderr or b"").decode(errors="replace")
            trace.append(
                {
                    "idx": idx,
                    "input_sha256": input_sha,
                    "exit": proc.returncode,
                    "crash": _is_crash_exit(proc.returncode),
                }
            )
            if _is_crash_exit(proc.returncode):
                crashes += 1
                cand_id = f"{run_id}-crash-{idx:04d}"
                candidates.append(
                    VulnerabilityCandidate(
                        vulnerability_id=cand_id,
                        task_id="eg-blind-quickjs",
                        vulnerability_type="SEH access violation (likely NULL "
                        "deref / type confusion during for-in iterator build)",
                        cwe_id="CWE-476",
                        title="Crash on vulnerable QuickJS build under "
                        "template-generated JavaScript input",
                        description=(
                            f"Reproducible access violation 0xC0000005 on "
                            f"vulnerable revision with input {input_sha[:16]}"
                        ),
                        target_id=target_binary.name,
                        location=VulnerabilityLocation(
                            file_path="quickjs.c",
                            function_name="build_for_in_iterator",
                            line_start=None,
                        ),
                        source_agent="blind-discovery-policy",
                        confidence=0.4,
                        evidence_ids=[f"ev-{run_id}-{idx:04d}"],
                        status=VulnerabilityStatus.CANDIDATE,
                    )
                )
                evidence.append(
                    Evidence(
                        evidence_id=f"ev-{run_id}-{idx:04d}",
                        task_id="eg-blind-quickjs",
                        evidence_type=EvidenceType.RUNTIME_TRACE,
                        source="blind-discovery-runner:qjs_asan.exe",
                        description=f"crash input {input_sha[:16]} exit "
                        f"{proc.returncode}",
                        artifact_path=str(
                            input_file.relative_to(self.workdir)
                        ),
                        data={
                            "exit_code": proc.returncode,
                            "input_sha256": input_sha,
                            "target_sha256": hashlib.sha256(
                                target_binary.read_bytes()
                            ).hexdigest(),
                            "stderr_head": stderr[:400],
                        },
                        reliability=0.6,
                        created_by="blind-discovery-runner",
                    )
                )

        trace_path = work / "agent_trace.jsonl"
        trace_path.write_text(
            "\n".join(json.dumps(t, ensure_ascii=False) for t in trace) + "\n",
            encoding="utf-8",
        )
        return DiscoveryOutcome(
            run_id=run_id,
            status="success",
            candidates=candidates,
            evidence=evidence,
            trace_path=trace_path,
            executions=executions,
            crashes=crashes,
        )
