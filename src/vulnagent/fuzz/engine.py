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

        executions = 0
        crashes = 0

        unique_signatures: set[str] = set()

        crash_fingerprints: set[str] = set()

        evidence: list[Evidence] = []

        # -------------------------------------------------
        # 6. Seed -> Mutation -> Execution
        # -------------------------------------------------

        for seed_index, seed in enumerate(
            seed_inputs
        ):

            mutated_inputs = (
                self.mutator.mutate(
                    seed,
                    count=self.mutation_count,
                )
            )

            for mutation_index, input_data in enumerate(
                mutated_inputs
            ):

                result = self.executor.execute(
                    target=target,
                    input_data=input_data,
                    work_dir=work_dir,
                )

                executions += 1

                unique_signatures.add(
                    result.signature
                )

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
            executed=True,
            crashes=crashes,
            coverage=coverage_proxy,
            evidence=evidence,
            metadata={
                "executions": executions,
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
            },
        )

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
                "input_sha256": input_hash,

                # Step 21:
                # Runtime trace collected by SandboxManager.
                "runtime_trace": runtime_trace,
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

                # Step 21:
                # Preserve runtime trace together
                # with the execution output.
                "runtime_trace": runtime_trace,
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
                    },
                    reliability=0.9,
                    created_by="fuzz",
                )
            )
        return evidence
