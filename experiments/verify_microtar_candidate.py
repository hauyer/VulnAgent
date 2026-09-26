"""Complete the formal main chain for the microtar clue (S5 review card).

Loads the frozen candidate + evidence from p1c-microtar-exploration, runs the
layered-v1 EvidenceVerifier (the only boundary allowed to write
CONFIRMED/REJECTED/UNCERTAIN), and persists verification.jsonl.  The verdict
is a deterministic function of the evidence; this script records, it does not
judge.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXP = ROOT / "artifacts" / "experiments" / "p1c-microtar-exploration"


def load_rows(name: str) -> list[dict]:
    p = EXP / name
    if not p.is_file():
        return []
    return [json.loads(line) for line in p.read_text(encoding="utf-8").splitlines() if line.strip()]


async def main() -> None:
    from vulnagent.contracts import Evidence, VerificationContext, VulnerabilityCandidate
    from vulnagent.verification.evidence_verifier import EvidenceVerifier

    cand_rows = load_rows("candidates.jsonl")
    ev_rows = load_rows("evidence.jsonl")
    if not cand_rows:
        print("no candidates; nothing to verify")
        return

    evidence = [Evidence(**row) for row in ev_rows]
    verifier = EvidenceVerifier(strategy_version="layered-v1")
    records: list[dict] = []
    for row in cand_rows:
        candidate = VulnerabilityCandidate(**row)
        context = VerificationContext(task_id=candidate.task_id, evidence=evidence)
        result = await verifier.verify(candidate, context)
        record = {
            "vulnerability_id": result.vulnerability_id,
            "task_id": result.task_id,
            "status": result.status.value,
            "confidence": result.confidence,
            "rationale": result.rationale,
            "evidence_ids": result.evidence_ids,
            "metadata": result.metadata,
            "strategy_version": verifier.strategy_version,
        }
        records.append(record)
        print(
            f"{result.vulnerability_id}: {result.status.value} "
            f"conf={result.confidence:.2f} "
            f"layers={result.metadata.get('layers')}"
        )

    (EXP / "verification.jsonl").write_text(
        "\n".join(json.dumps(r, ensure_ascii=False) for r in records) + "\n",
        encoding="utf-8",
    )
    print(f"wrote {len(records)} verification record(s) -> {EXP / 'verification.jsonl'}")


if __name__ == "__main__":
    asyncio.run(main())
