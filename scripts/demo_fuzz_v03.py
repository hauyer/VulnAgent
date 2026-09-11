"""Run the authorized local static→guided-fuzz→verification demo."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
from pathlib import Path

from vulnagent.bootstrap import build_v03_source_application
from vulnagent.contracts import EvidenceType, Target, TargetType, TaskStatus
from vulnagent.settings import Settings


LOGGER = logging.getLogger("vulnagent.demo.fuzz")
ROOT = Path(__file__).resolve().parents[1]


async def run_demo(target: Path, seed_dir: Path, output: Path) -> dict[str, object]:
    """Run one explicitly authorized target through the canonical runtime."""
    services = build_v03_source_application(
        settings=Settings(vulnagent_profile="v03-source")
    )
    task = services.task_manager.create_task(
        Target(
            target_id="guided-fuzz-demo",
            path=str(target.resolve()),
            target_type=TargetType.SOURCE,
            language="python",
            metadata={
                "fuzz_authorized": True,
                "dynamic_validation": True,
                "seed_dir": str(seed_dir.resolve()),
            },
        )
    )
    context = await services.orchestrator.run(task.task_id)
    if context.task.status is not TaskStatus.COMPLETED:
        raise RuntimeError(context.task.error or "fuzz demo did not complete")
    fuzz_message = next(
        item for item in context.messages if item.sender == "fuzz"
    )
    crash_evidence = [
        item
        for item in context.evidence
        if item.evidence_type is EvidenceType.CRASH_LOG
    ]
    result: dict[str, object] = {
        "task_id": task.task_id,
        "status": context.task.status.value,
        "target": str(target.resolve()),
        "authorization": "local_self_authored_explicit",
        "route_history": context.task.metadata.get("termination", {}).get(
            "route_history", []
        ),
        "fuzz": fuzz_message.payload,
        "crash_evidence_count": len(crash_evidence),
        "findings": [item.model_dump(mode="json") for item in context.findings],
        "verifications": [
            item.model_dump(mode="json") for item in context.verifications
        ],
        "report": context.reports[-1].content,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the canonical guided-fuzz demo.")
    parser.add_argument(
        "--target",
        type=Path,
        default=ROOT / "samples" / "fuzz_demo" / "target.py",
    )
    parser.add_argument(
        "--seed-dir",
        type=Path,
        default=ROOT / "samples" / "fuzz_demo" / "seeds",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "artifacts" / "demos" / "fuzz-v03.json",
    )
    args = parser.parse_args()
    result = asyncio.run(
        run_demo(args.target.resolve(), args.seed_dir.resolve(), args.output.resolve())
    )
    LOGGER.info(
        "status=%s crashes=%d strategy=%s output=%s",
        result["status"],
        result["crash_evidence_count"],
        result["fuzz"]["metadata"]["mutation_strategy"],
        args.output.resolve(),
    )


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    main()
