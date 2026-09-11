"""Controlled fuzzing engine."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from vulnagent.contracts import (
    Evidence,
    EvidenceType,
    FuzzRequest,
    FuzzResult,
)
from vulnagent.fuzz.executor import ControlledExecutor
from vulnagent.fuzz.guidance import MutationCase, RiskGuidedMutationPlanner
from vulnagent.fuzz.mutation import MutationEngine
from vulnagent.utils.ids import new_evidence_id


class ControlledFuzzEngine:
    """Authorization-gated fuzzing engine."""

    def __init__(
        self,
        timeout_seconds: float = 1.0,
        mutation_count: int = 8,
        seed: int = 0,
    ) -> None:
        self.executor = ControlledExecutor(
            timeout_seconds=timeout_seconds,
        )

        self.mutator = MutationEngine(
            seed=seed,
        )

        self.guidance = RiskGuidedMutationPlanner()

        self.mutation_count = mutation_count

    async def run(
        self,
        request: FuzzRequest,
    ) -> FuzzResult:
        """Run controlled fuzzing."""

        # -------------------------------------------------
        # 1. Authorization check
        # -------------------------------------------------

        if not request.authorized:
            return FuzzResult(
                task_id=request.task_id,
                target_id=request.target_id,
                executed=False,
                crashes=0,
                metadata={
                    "reason": "target_not_authorized",
                },
            )

        # -------------------------------------------------
        # 2. Target validation
        # -------------------------------------------------

        target = Path(
            request.target_path
        ).resolve()

        if not target.exists():
            return FuzzResult(
                task_id=request.task_id,
                target_id=request.target_id,
                executed=False,
                crashes=0,
                metadata={
                    "reason": "target_not_found",
                },
            )

        if not target.is_file():
            return FuzzResult(
                task_id=request.task_id,
                target_id=request.target_id,
                executed=False,
                crashes=0,
                metadata={
                    "reason": "target_is_not_file",
                },
            )

        # -------------------------------------------------
        # 3. Create isolated working directory
        # -------------------------------------------------

        work_dir = (
            target.parent
            / ".vulnagent_fuzz_work"
        )

        work_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        # -------------------------------------------------
        # 4. Load seeds
        # -------------------------------------------------

        seed_inputs = self._load_seeds(
            request
        )

        if not seed_inputs:
            seed_inputs = [b""]

        # -------------------------------------------------
        # 5. Runtime statistics
        # -------------------------------------------------

        attempts = 0
        executions = 0
        launch_failures = 0
        crashes = 0

        unique_signatures: set[str] = set()

        crash_fingerprints: set[str] = set()

        evidence: list[Evidence] = []
        sandbox_profiles: dict[str, dict[str, Any]] = {}

        risk_hints = self._risk_hints(request)
        guidance_types = self.guidance.normalize_hints(risk_hints)
        guided_mutations = 0
        generic_mutations = 0
        if guidance_types:
            evidence.append(
                Evidence(
                    evidence_id=new_evidence_id(),
                    task_id=request.task_id,
                    evidence_type=EvidenceType.TOOL_RESULT,
                    source="risk_guided_mutation_planner",
                    description=(
                        "Structured static findings selected bounded, non-exploit "
                        "mutation classes for authorized dynamic validation."
                    ),
                    data={
                        "risk_types": list(guidance_types),
                        "source_finding_ids": request.metadata.get(
                            "guidance_source_finding_ids",
                            [],
                        ),
                        "payload_policy": "inert_markers_and_parser_boundaries",
                    },
                    reliability=0.85,
                    created_by="fuzz",
                )
            )

        # -------------------------------------------------
        # 6. Seed -> Mutation -> Execution
        # -------------------------------------------------

        for seed_index, seed in enumerate(
            seed_inputs
        ):

            mutation_cases = self._mutation_cases(
                seed,
                risk_hints,
            )

            for mutation_index, mutation_case in enumerate(
                mutation_cases
            ):

                input_data = mutation_case.data
                if mutation_case.risk_type is None:
                    generic_mutations += 1
                else:
                    guided_mutations += 1

                result = self.executor.execute(
                    target=target,
                    input_data=input_data,
                    work_dir=work_dir,
                )

                sandbox_metadata = getattr(result, "sandbox_metadata", {})
                if isinstance(sandbox_metadata, dict):
                    backend_name = sandbox_metadata.get("backend_name")
                    if isinstance(backend_name, str) and backend_name:
                        sandbox_profiles[backend_name] = {
                            "backend_name": backend_name,
                            "enforced_controls": list(
                                sandbox_metadata.get("enforced_controls", [])
                            ),
                            "unsupported_controls": list(
                                sandbox_metadata.get("unsupported_controls", [])
                            ),
                            "network_isolation_enforced": bool(
                                sandbox_metadata.get("network_isolation_enforced", False)
                            ),
                            "filesystem_isolation_enforced": bool(
                                sandbox_metadata.get("filesystem_isolation_enforced", False)
                            ),
                            "resource_limits": dict(
                                sandbox_metadata.get("resource_limits", {})
                            ),
                            "fail_closed": bool(
                                sandbox_metadata.get("fail_closed", False)
                            ),
                        }

                attempts += 1

                if result.executed:
                    executions += 1
                    unique_signatures.add(
                        result.signature
                    )
                else:
                    launch_failures += 1

                # -------------------------------------------------
                # 7. Crash detection and deduplication
                # -------------------------------------------------

                if result.crashed:

                    fingerprint = (
                        self._crash_fingerprint(
                            result.stderr,
                            result.returncode,
                        )
                    )

                    if (
                        fingerprint
                        not in crash_fingerprints
                    ):
                        crash_fingerprints.add(
                            fingerprint
                        )

                        crashes += 1

                # -------------------------------------------------
                # 8. Generate Evidence
                # -------------------------------------------------

                evidence.extend(
                    self._build_evidence(
                        request=request,
                        result=result,
                        input_data=input_data,
                        seed_index=seed_index,
                        mutation_index=mutation_index,
                        mutation_strategy=mutation_case.strategy,
                        risk_type=mutation_case.risk_type,
                    )
                )

        # -------------------------------------------------
        # 9. Coverage proxy
        # -------------------------------------------------

        coverage_proxy = None

        if executions > 0:
            coverage_proxy = (
                len(unique_signatures)
                / executions
            )

        # -------------------------------------------------
        # 10. Return FuzzResult
        # -------------------------------------------------

        return FuzzResult(
            task_id=request.task_id,
            target_id=request.target_id,
            executed=executions > 0,
            crashes=crashes,
            coverage=coverage_proxy,
            evidence=evidence,
            metadata={
                "attempts": attempts,
                "executions": executions,
                "launch_failures": launch_failures,
                "unique_execution_signatures": (
                    len(unique_signatures)
                ),
                "coverage_kind": (
                    "execution_signature_proxy"
                ),
                "mutation_count": (
                    self.mutation_count
                ),
                "seed_count": len(seed_inputs),
                "mutation_strategy": (
                    "hybrid_risk_guided" if guidance_types else "generic"
                ),
                "guidance_risk_types": list(guidance_types),
                "guidance_hint_count": len(risk_hints),
                "guided_mutations": guided_mutations,
                "generic_mutations": generic_mutations,
                "crash_fingerprints": sorted(crash_fingerprints),
                "sandbox_profiles": [
                    sandbox_profiles[name] for name in sorted(sandbox_profiles)
                ],
            },
        )

    def _mutation_cases(
        self,
        seed: bytes,
        risk_hints: list[dict[str, Any]],
    ) -> list[MutationCase]:
        """Allocate a fixed per-seed budget between guided and generic probes."""
        if self.mutation_count <= 0:
            return []
        if not risk_hints:
            return [
                MutationCase(data=item, strategy="generic_random")
                for item in self.mutator.mutate(seed, count=self.mutation_count)
            ]

        guided_budget = max(1, (self.mutation_count + 1) // 2)
        guided = self.guidance.generate(
            seed,
            risk_hints,
            count=guided_budget,
        )
        generic_budget = self.mutation_count - len(guided)
        generic = [
            MutationCase(data=item, strategy="generic_random")
            for item in self.mutator.mutate(seed, count=generic_budget)
        ]
        return [*guided, *generic]

    @staticmethod
    def _risk_hints(request: FuzzRequest) -> list[dict[str, Any]]:
        """Read only bounded structured hint dictionaries from request metadata."""
        value = request.metadata.get("risk_hints", [])
        if not isinstance(value, list):
            return []
        return [dict(item) for item in value[:16] if isinstance(item, dict)]

    # =====================================================
    # Seed loader
    # =====================================================

    def _load_seeds(
        self,
        request: FuzzRequest,
    ) -> list[bytes]:
        """Load seed files from metadata."""

        seed_dir_value = (
            request.metadata.get(
                "seed_dir"
            )
        )

        if not seed_dir_value:
            return []

        seed_dir = Path(
            str(seed_dir_value)
        ).resolve()

        if not seed_dir.exists():
            return []

        if not seed_dir.is_dir():
            return []

        seeds: list[bytes] = []

        for path in sorted(
            seed_dir.iterdir()
        ):

            if not path.is_file():
                continue

            try:
                data = path.read_bytes()

            except OSError:
                continue

            # Limit one seed to 1 MB.
            if len(data) <= 1024 * 1024:
                seeds.append(data)

        return seeds

    # =====================================================
    # Crash fingerprint
    # =====================================================

    def _crash_fingerprint(
        self,
        stderr: bytes,
        returncode: int | None,
    ) -> str:
        """Create a stable crash fingerprint."""

        data = (
            str(returncode).encode()
            + b":"
            + stderr[:4096]
        )

        return hashlib.sha256(
            data
        ).hexdigest()

    # =====================================================
    # Evidence
    # =====================================================

    def _build_evidence(
        self,
        request: FuzzRequest,
        result: Any,
        input_data: bytes,
        seed_index: int,
        mutation_index: int,
        mutation_strategy: str,
        risk_type: str | None,
    ) -> list[Evidence]:
        """Build Evidence objects for one execution."""

        input_hash = hashlib.sha256(
            input_data
        ).hexdigest()

        # -------------------------------------------------
        # Runtime trace compatibility
        # -------------------------------------------------
        #
        # ControlledExecutor in Step 21 will provide
        # runtime_trace.
        #
        # getattr() keeps the fuzz engine compatible with
        # an older ExecutionResult during the transition.
        #

        runtime_trace = list(
            getattr(
                result,
                "runtime_trace",
                [],
            )
        )
        sandbox_metadata = getattr(result, "sandbox_metadata", {})
        if not isinstance(sandbox_metadata, dict):
            sandbox_metadata = {}

        # -------------------------------------------------
        # Fuzz input evidence
        # -------------------------------------------------

        input_evidence = Evidence(
            evidence_id=new_evidence_id(),
            task_id=request.task_id,
            evidence_type=(
                EvidenceType.FUZZ_INPUT
            ),
            source="mutation_engine",
            description=(
                "Mutation input used "
                "for controlled execution."
            ),
            data={
                "seed_index": seed_index,
                "mutation_index": (
                    mutation_index
                ),
                "sha256": input_hash,
                "size": len(input_data),
                "mutation_strategy": mutation_strategy,
                "risk_type": risk_type,
            },
            reliability=0.9,
            created_by="fuzz",
        )

        # -------------------------------------------------
        # Runtime evidence
        # -------------------------------------------------

        runtime_evidence = Evidence(
            evidence_id=new_evidence_id(),
            task_id=request.task_id,
            evidence_type=(
                EvidenceType.RUNTIME_TRACE
            ),
            source="controlled_fuzz_executor",
            description=(
                "One controlled fuzz "
                "execution result."
            ),
            data={
                "seed_index": seed_index,
                "mutation_index": (
                    mutation_index
                ),
                "returncode": (
                    result.returncode
                ),
                "executed": result.executed,
                "timed_out": (
                    result.timed_out
                ),
                "crashed": (
                    result.crashed
                ),
                "elapsed_ms": (
                    result.elapsed_ms
                ),
                "signature": (
                    result.signature
                ),
                "error": result.error,
                "input_sha256": input_hash,
                "mutation_strategy": mutation_strategy,
                "risk_type": risk_type,

                # Step 21:
                # Runtime trace collected by SandboxManager.
                "runtime_trace": runtime_trace,
                "sandbox": sandbox_metadata,
            },
            reliability=0.8,
            created_by="fuzz",
        )

        # -------------------------------------------------
        # Tool result evidence
        # -------------------------------------------------

        result_evidence = Evidence(
            evidence_id=new_evidence_id(),
            task_id=request.task_id,
            evidence_type=(
                EvidenceType.TOOL_RESULT
            ),
            source="controlled_fuzz_executor",
            description=(
                "Fuzz execution "
                "output summary."
            ),
            data={
                "returncode": (
                    result.returncode
                ),
                "executed": result.executed,
                "timed_out": (
                    result.timed_out
                ),
                "crashed": (
                    result.crashed
                ),
                "stdout": (
                    result.stdout[
                        :2048
                    ].decode(
                        errors="replace"
                    )
                ),
                "stderr": (
                    result.stderr[
                        :2048
                    ].decode(
                        errors="replace"
                    )
                ),
                "error": result.error,
                "mutation_strategy": mutation_strategy,
                "risk_type": risk_type,

                # Step 21:
                # Preserve runtime trace together
                # with the execution output.
                "runtime_trace": runtime_trace,
                "sandbox": sandbox_metadata,
            },
            reliability=0.8,
            created_by="fuzz",
        )

        evidence = [
            input_evidence,
            runtime_evidence,
            result_evidence,
        ]
        if result.crashed:
            evidence.append(
                Evidence(
                    evidence_id=new_evidence_id(),
                    task_id=request.task_id,
                    evidence_type=EvidenceType.CRASH_LOG,
                    source="controlled_fuzz_executor",
                    description="Authorized local execution exited abnormally.",
                    data={
                        "returncode": result.returncode,
                        "stderr": result.stderr[:2048].decode(errors="replace"),
                        "input_sha256": input_hash,
                        "signature": result.signature,
                        "seed_index": seed_index,
                        "mutation_index": mutation_index,
                        "mutation_strategy": mutation_strategy,
                        "risk_type": risk_type,
                    },
                    reliability=0.9,
                    created_by="fuzz",
                )
            )
        return evidence
