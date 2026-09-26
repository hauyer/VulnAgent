"""S1: target-agnostic blind discovery runner.

The runner is the *external experiment scheduler* for a blind discovery run.
It accepts only a de-identified :class:`AgentTargetSpec` (no CVE id, no CWE
label, no patch name, no trigger payload) and:

1. proposes raw inputs through a :class:`DiscoveryPolicy` (or fixed seed files),
2. executes each input against the target through a
   :class:`BoundedTargetExecutor` (which enforces resource limits and reports
   only observations),
3. triages crash observations into root-cause clusters
   (:class:`ObservationTriage` -- target-agnostic),
4. emits one ``VulnerabilityCandidate`` per cluster whose fields are derived
   only from observations: ``vulnerability_type`` from the crash kind /
   sanitizer, ``cwe_id`` stays ``None`` unless the observation itself carries
   it, ``location`` comes only from symbolized stack frames.

A crash exit is a fault *observation*, never a conclusion: the runner never
writes CWE ids, function names or file names into a candidate unless the
observation evidence supports them.  ``KnownCaseFeasibilityPolicy`` is kept
in this module strictly as the archived feasibility baseline for the QuickJS
case study; it is NOT used by blind discovery runs.
"""

from __future__ import annotations

import hashlib
import json
import random
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from vulnagent.benchmark.discovery_ports import (
    AgentTargetSpec,
    BoundedTargetExecutor,
    DiscoveryPolicy,
    ExecutionObservation,
    ObservationTriage,
    RootCauseCluster,
    SandboxBoundedExecutor,
)
from vulnagent.contracts import (
    Evidence,
    EvidenceType,
    VulnerabilityCandidate,
    VulnerabilityLocation,
    VulnerabilityStatus,
)


@dataclass
class DiscoveryOutcome:
    run_id: str
    status: str  # success / timeout / error / unsupported
    candidates: list[VulnerabilityCandidate] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    trace_path: Path | None = None
    executions: int = 0
    crashes: int = 0
    clusters: list[RootCauseCluster] = field(default_factory=list)
    reason: str = ""


class KnownCaseFeasibilityPolicy:
    """ARCHIVED feasibility baseline (QuickJS case study only).

    This template corpus was written around the known trigger path of
    CVE-2023-48183 (eval-in-arrow scope feeding a for-in iterator).  It is
    kept for provenance and case-study reproduction, and is explicitly NOT a
    blind discovery policy.  Blind runs must use
    :class:`GenericJavaScriptPolicy` or a target-neutral corpus.
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

    def propose_inputs(
        self, spec: AgentTargetSpec, *, seed: int
    ) -> list[bytes]:
        rng = random.Random(seed)
        return [p.encode("utf-8") for p in self.generate(rng, 100)]


class GenericJavaScriptPolicy:
    """Blind discovery policy: generic JavaScript language-semantics corpus.

    Templates exercise ordinary language constructs any JS engine must
    handle (classes, inheritance, arrow-function scope, ``eval``, iteration
    over computed objects, getters, proxies, spread, destructuring).  They
    contain no CVE identifiers, no patch file names and no label knowledge;
    they are not tailored to any specific target.
    """

    def generate(self, rng: random.Random, count: int) -> list[bytes]:
        names = ["A", "B", "C", "X", "Y", "T", "Base", "Derived"]
        templates: list[str] = []

        # Class inheritance with arrow-scope eval feeding an iterator.
        def class_eval_loop() -> str:
            base = rng.choice(names)
            derived = rng.choice([n for n in names if n != base])
            scope = rng.choice(
                [
                    "var g = (() => eval('this'))();",
                    "var g = (() => this)();",
                    "var g = eval('this');",
                    "var g = function () { return eval('this'); }();",
                ]
            )
            target = rng.choice(
                ["g", "g || {}", "g && []", "Object(g)", "g === undefined ? {} : g"]
            )
            loop = rng.choice(
                [
                    f"for (var k in {target}) {{}}",
                    f"for (var k of Object.keys({target} || {{}})) {{}}",
                    f"var n = 0; for (var k in {target}) {{ n++; }}",
                    f"for (var k in {target}) {{ void k; }}",
                ]
            )
            return (
                f"class {base} {{}}\n"
                f"class {derived} extends {base} {{\n"
                f"  constructor() {{\n    {scope}\n    super();\n    {loop}\n  }}\n"
                f"}}\nnew {derived}();\n"
            )

        # Ordinary property iteration over various object sources.
        def object_loop() -> str:
            source = rng.choice(
                [
                    "{}",
                    "{a:1,b:2}",
                    "Object.create(null)",
                    "new Map([['a',1]])",
                    "new Set([1,2])",
                    "[1,2,3]",
                    "JSON.parse('{\"a\":1}')",
                    "new Proxy({}, {})",
                ]
            )
            loop = rng.choice(
                [
                    f"for (var k in {source}) {{ void k; }}",
                    f"for (var k of Object.keys({source})) {{ void k; }}",
                    f"for (var k of {source}) {{ void k; }}",
                    f"var n = 0; for (var k in {source}) {{ n++; }}",
                ]
            )
            return loop + "\n"

        # Arrow / eval scope probes with computed keys and spread.
        def scope_probe() -> str:
            key = rng.choice(["'a'", "'0'", "1", "'length'"])
            spread = rng.choice(
                [
                    "var o = {a:1}; var c = {...o};",
                    "var a = [1]; var b = [...a];",
                    "var o = {a:1}; var c = Object.assign({}, o);",
                    "var a = [1]; var b = a.slice();",
                ]
            )
            eval_use = rng.choice(
                [
                    "var v = eval('this');",
                    "var v = (() => eval('this'))();",
                    "var v = Function('return this')();",
                ]
            )
            return f"{spread}\n{eval_use}\nvar t = {{}}; t[{key}] = 1;\n"

        # Getters / proxies exercising [[Get]] during iteration.
        def proxy_probe() -> str:
            return (
                "var target = {};\n"
                "var p = new Proxy(target, { get(t, k) { return t[k]; } });\n"
                "p.a = 1;\n"
                "for (var k in p) { void k; }\n"
                "var g = Object.getPrototypeOf(p); void g;\n"
            )

        builders = [class_eval_loop, object_loop, scope_probe, proxy_probe]
        programs: list[str] = []
        for _ in range(count):
            programs.append(rng.choice(builders)())
        return [program.encode("utf-8") for program in programs]

    def propose_inputs(
        self, spec: AgentTargetSpec, *, seed: int
    ) -> list[bytes]:
        rng = random.Random(seed)
        return self.generate(rng, spec.max_executions)


class GenericWasmPolicy:
    """Blind discovery policy for WebAssembly binary targets.

    Byte-level mutations over the seed corpus: bit flips, byte insert/delete,
    chunk duplication/splicing and random reshuffles.  No label knowledge (no
    CVE ids, no function names, no trigger templates); the policy only knows
    the wasm binary shape (magic + version) to keep mutations on-seed.
    """

    def __init__(self) -> None:
        self._magic = b"\x00asm"

    @staticmethod
    def _mutate(rng: random.Random, data: bytearray) -> bytearray:
        out = bytearray(data)
        op = rng.randrange(6)
        if op == 0 and out:  # bit flip
            idx = rng.randrange(len(out))
            out[idx] ^= 1 << rng.randrange(8)
        elif op == 1 and out:  # random byte overwrite
            idx = rng.randrange(len(out))
            out[idx] = rng.randrange(256)
        elif op == 2 and out:  # insert a random byte
            idx = rng.randrange(len(out) + 1)
            out.insert(idx, rng.randrange(256))
        elif op == 3 and out:  # delete a byte
            idx = rng.randrange(len(out))
            del out[idx]
        elif op == 4 and len(out) >= 2:  # duplicate a chunk
            a = rng.randrange(len(out) - 1)
            b = min(len(out), a + 1 + rng.randrange(16))
            out[a:b] = out[a:b] * (1 + rng.randrange(3))
        elif op == 5 and len(out) >= 2:  # splice two halves
            cut = rng.randrange(1, len(out))
            out[:] = out[cut:] + out[:cut]
        return out

    def propose_inputs(
        self, spec: AgentTargetSpec, *, seed: int
    ) -> list[bytes]:
        rng = random.Random(seed)
        seeds = sorted(spec.seed_dir.glob("*"))
        base = (
            seeds[rng.randrange(len(seeds))].read_bytes() if seeds else self._magic
        )
        count = max(1, spec.max_executions)
        outputs: list[bytes] = []
        for _ in range(count):
            variant = self._mutate(rng, bytearray(base))
            if not variant.startswith(self._magic):
                variant = self._magic + variant[len(self._magic):]
            outputs.append(bytes(variant))
        return outputs


class BlindDiscoveryRunner:
    """Run a blind discovery loop against any built, authorized target."""

    def __init__(self, workdir: Path) -> None:
        self.workdir = Path(workdir)
        self.workdir.mkdir(parents=True, exist_ok=True)

    def run(
        self,
        *,
        spec: AgentTargetSpec,
        executor: BoundedTargetExecutor | None = None,
        policy: DiscoveryPolicy | None = None,
        seed: int = 7,
        extra_seed_inputs: list[bytes] | None = None,
    ) -> DiscoveryOutcome:
        run_id = f"blind-{uuid.uuid4().hex[:8]}"
        trace: list[dict[str, Any]] = []
        rng = random.Random(seed)

        executor = executor or SandboxBoundedExecutor()
        work = self.workdir / run_id
        inputs_dir = work / "inputs"
        inputs_dir.mkdir(parents=True, exist_ok=True)

        proposed: list[bytes] = []
        if policy is not None:
            proposed.extend(policy.propose_inputs(spec, seed=seed))
        if extra_seed_inputs:
            proposed.extend(extra_seed_inputs)

        candidates: list[VulnerabilityCandidate] = []
        evidence: list[Evidence] = []
        observations: list[ExecutionObservation] = []
        executions = 0
        crashes = 0

        deadline = datetime.now(timezone.utc).timestamp() + spec.time_budget_seconds
        for idx, payload in enumerate(proposed):
            if idx >= spec.max_executions:
                trace.append({"event": "execution_budget", "idx": idx})
                break
            if datetime.now(timezone.utc).timestamp() > deadline:
                trace.append({"event": "time_budget", "idx": idx})
                break
            input_file = inputs_dir / f"in_{idx:04d}.in"
            input_file.write_bytes(payload)
            executions += 1
            obs = executor.execute(spec, input_file)
            observations.append(obs)
            trace.append(
                {
                    "idx": idx,
                    "input_sha256": obs.input_sha256,
                    "exit": obs.exit_code,
                    "crashed": obs.crashed,
                    "timed_out": obs.timed_out,
                    "sanitizer_kind": obs.sanitizer_kind,
                    "stack_frames": list(obs.stack_frames),
                    "error": obs.error,
                }
            )
            if obs.crashed:
                crashes += 1

        clusters = ObservationTriage.cluster(observations, run_id=run_id)

        for cluster in clusters:
            cand_id = f"{run_id}-{cluster.cluster_id.rsplit('-', 1)[-1]}"
            ev_ids: list[str] = []
            for hash_idx, input_sha in enumerate(cluster.observation_hashes):
                ev_id = f"ev-{cand_id}-{hash_idx:02d}"
                ev_ids.append(ev_id)
                evidence.append(
                    Evidence(
                        evidence_id=ev_id,
                        task_id=spec.opaque_case_id,
                        evidence_type=EvidenceType.CRASH_LOG,
                        source="blind-discovery-runner",
                        description=(
                            f"crash observation input {input_sha[:16]} "
                            f"cluster {cluster.key}"
                        ),
                        artifact_path=str(inputs_dir.relative_to(self.workdir)),
                        data={
                            "input_sha256": input_sha,
                            "target_sha256": spec.target_sha256 or "",
                            "crash_code_kind": cluster.crash_code_kind,
                            "sanitizer_kind": cluster.sanitizer_kind,
                            "cluster_key": cluster.key,
                            "cluster_id": cluster.cluster_id,
                        },
                        reliability=0.7,
                        created_by="blind-discovery-runner",
                    )
                )

            location = None
            if cluster.top_frame:
                file_path, _, line_no = cluster.top_frame.rpartition(":")
                location = VulnerabilityLocation(
                    file_path=file_path or None,
                    line_start=int(line_no) if line_no.isdigit() else None,
                )

            vulnerability_type = (
                cluster.crash_code_kind
                or (
                    f"sanitizer: {cluster.sanitizer_kind}"
                    if cluster.sanitizer_kind
                    else "abnormal exit"
                )
            )
            candidates.append(
                VulnerabilityCandidate(
                    vulnerability_id=cand_id,
                    task_id=spec.opaque_case_id,
                    vulnerability_type=vulnerability_type,
                    cwe_id=None,  # never invented; only observations fill this
                    title=(
                        "Reproducible abnormal target exit under generated input"
                    ),
                    description=(
                        f"Reproducible fault observation on the target revision "
                        f"with {len(cluster.observation_hashes)} crash input(s); "
                        f"root-cause key {cluster.key}. CWE and precise location "
                        f"require independent source/runtime evidence."
                    ),
                    target_id=Path(spec.target_path).name,
                    location=location,
                    source_agent="blind-discovery-policy",
                    confidence=0.4,
                    evidence_ids=ev_ids,
                    status=VulnerabilityStatus.CANDIDATE,
                    metadata={
                        "cluster_id": cluster.cluster_id,
                        "root_cause_key": cluster.key,
                        "raw_crash_count": len(cluster.observation_hashes),
                        "crash_code_kind": cluster.crash_code_kind,
                        "sanitizer_kind": cluster.sanitizer_kind,
                        "top_frame": cluster.top_frame,
                        "isolation_capabilities": sorted(
                            next(
                                (
                                    obs.isolation_capabilities
                                    for obs in observations
                                    if obs.crashed
                                ),
                                (),
                            )
                        ),
                    },
                )
            )

        trace_path = work / "agent_trace.jsonl"
        trace_path.write_text(
            "\n".join(json.dumps(t, ensure_ascii=False) for t in trace) + "\n",
            encoding="utf-8",
        )
        status = "success"
        reason = ""
        if not observations:
            status = "unsupported"
            reason = "no inputs were proposed"
        elif not any(obs.crashed for obs in observations) and executions > 0:
            status = "success"
            reason = "zero_findings (negative result recorded)"
        return DiscoveryOutcome(
            run_id=run_id,
            status=status,
            candidates=candidates,
            evidence=evidence,
            trace_path=trace_path,
            executions=executions,
            crashes=crashes,
            clusters=clusters,
            reason=reason,
        )


def write_candidate_rows(path: Path, outcome: DiscoveryOutcome) -> None:
    """Serialize candidates to evaluator-consumable rows with cluster facts."""
    path.parent.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, Any]] = []
    for candidate in outcome.candidates:
        loc = candidate.location
        rows.append(
            {
                "case_id": candidate.task_id,
                "candidate_id": candidate.vulnerability_id,
                "vulnerability_type": candidate.vulnerability_type,
                "cwe_id": candidate.cwe_id or "",
                "location": (
                    f"{loc.file_path}:{loc.line_start or 0}" if loc else ""
                ),
                "root_cause_cluster": candidate.metadata.get(
                    "root_cause_key", ""
                ),
                "raw_crash_count": candidate.metadata.get("raw_crash_count", 1),
                "evidence_count": len(candidate.evidence_ids),
                "status": "success",
                "note": "blind discovery candidate (generated input)",
            }
        )
    path.write_text(
        "\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n"
        if rows
        else "",
        encoding="utf-8",
    )


__all__ = [
    "BlindDiscoveryRunner",
    "DiscoveryOutcome",
    "GenericJavaScriptPolicy",
    "KnownCaseFeasibilityPolicy",
    "write_candidate_rows",
]
