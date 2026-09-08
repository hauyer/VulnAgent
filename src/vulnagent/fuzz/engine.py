"""Controlled fuzzing engine."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from vulnagent.contracts import Evidence, EvidenceType, FuzzRequest, FuzzResult
from vulnagent.fuzz.executor import ControlledExecutor
from vulnagent.fuzz.mutation import MutationEngine
from vulnagent.utils.ids import new_evidence_id


class ControlledFuzzEngine:
    """Authorization-gated fuzzing engine for local course samples."""

    def __init__(
        self,
        timeout_seconds: float = 1.0,
        mutation_count: int = 8,
        seed: int = 0,
    ) -> None:
        self.executor = ControlledExecutor(
            timeout_seconds=timeout_seconds,
        )

        self.mutator = MutationEngine(seed=seed)

        self.mutation_count = mutation_count

    async def run(self, request: FuzzRequest) -> FuzzResult:
        """Run controlled fuzzing."""

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

        target = Path(request.target_path).resolve()

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

        work_dir = target.parent / ".vulnagent_fuzz_work"
        work_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        seed_inputs = self._load_seeds(request)

        if not seed_inputs:
            seed_inputs = [b""]

        crashes = 0
        executions = 0
        unique_signatures: set[str] = set()

        evidence: list[Evidence] = []

        crash_fingerprints: set[str] = set()

        for seed_index, seed in enumerate(seed_inputs):

            mutated_inputs = self.mutator.mutate(
                seed,
                count=self.mutation_count,
            )

            for mutation_index, input_data in enumerate(mutated_inputs):

                result = self.executor.execute(
                    target=target,
                    input_data=input_data,
                    work_dir=work_dir,
                )

                executions += 1

                unique_signatures.add(result.signature)

                if result.crashed:
                    fingerprint = self._crash_fingerprint(
                        result.stderr,
                        result.returncode,
                    )

                    if fingerprint not in crash_fingerprints:
                        crash_fingerprints.add(fingerprint)
                        crashes += 1

                evidence.extend(
                    self._build_evidence(
                        request=request,
                        result=result,
                        input_data=input_data,
                        seed_index=seed_index,
                        mutation_index=mutation_index,
                    )
                )

        coverage_proxy = None

        if executions > 0:
            coverage_proxy = len(unique_signatures) / executions

        return FuzzResult(
            task_id=request.task_id,
            target_id=request.target_id,
            executed=True,
            crashes=crashes,
            coverage=coverage_proxy,
            evidence=evidence,
            metadata={
                "executions": executions,
                "unique_execution_signatures": len(unique_signatures),
                "coverage_kind": "execution_signature_proxy",
                "mutation_count": self.mutation_count,
                "seed_count": len(seed_inputs),
            },
        )

    def _load_seeds(
        self,
        request: FuzzRequest,
    ) -> list[bytes]:
        """Load seed files from metadata."""

        seed_dir_value = request.metadata.get("seed_dir")

        if not seed_dir_value:
            return []

        seed_dir = Path(str(seed_dir_value)).resolve()

        if not seed_dir.exists() or not seed_dir.is_dir():
            return []

        seeds: list[bytes] = []

        for path in sorted(seed_dir.iterdir()):
            if not path.is_file():
                continue

            try:
                data = path.read_bytes()

                if len(data) <= 1024 * 1024:
                    seeds.append(data)

            except OSError:
                continue

        return seeds

    def _crash_fingerprint(
        self,
        stderr: bytes,
        returncode: int | None,
    ) -> str:

        data = (
            str(returncode).encode()
            + b":"
            + stderr[:4096]
        )

        return hashlib.sha256(data).hexdigest()

    def _build_evidence(
        self,
        request: FuzzRequest,
        result: Any,
        input_data: bytes,
        seed_index: int,
        mutation_index: int,
    ) -> list[Evidence]:

        input_hash = hashlib.sha256(input_data).hexdigest()

        runtime_evidence = Evidence(
            evidence_id=new_evidence_id(),
            task_id=request.task_id,
            evidence_type=EvidenceType.RUNTIME_TRACE,
            source="controlled_fuzz_executor",
            description="One controlled fuzz execution result.",
            data={
                "seed_index": seed_index,
                "mutation_index": mutation_index,
                "returncode": result.returncode,
                "timed_out": result.timed_out,
                "crashed": result.crashed,
                "elapsed_ms": result.elapsed_ms,
                "signature": result.signature,
                "input_sha256": input_hash,
            },
            reliability=0.8,
            created_by="fuzz",
        )

        input_evidence = Evidence(
            evidence_id=new_evidence_id(),
            task_id=request.task_id,
            evidence_type=EvidenceType.FUZZ_INPUT,
            source="mutation_engine",
            description="Mutation input used for controlled execution.",
            data={
                "seed_index": seed_index,
                "mutation_index": mutation_index,
                "sha256": input_hash,
                "size": len(input_data),
            },
            reliability=0.9,
            created_by="fuzz",
        )

        result_evidence = Evidence(
            evidence_id=new_evidence_id(),
            task_id=request.task_id,
            evidence_type=EvidenceType.TOOL_RESULT,
            source="controlled_fuzz_executor",
            description="Fuzz execution output summary.",
            data={
                "returncode": result.returncode,
                "timed_out": result.timed_out,
                "crashed": result.crashed,
                "stdout": result.stdout[:2048].decode(
                    errors="replace"
                ),
                "stderr": result.stderr[:2048].decode(
                    errors="replace"
                ),
            },
            reliability=0.8,
            created_by="fuzz",
        )

        return [
            input_evidence,
            runtime_evidence,
            result_evidence,
        ]