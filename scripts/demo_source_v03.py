"""Run the real V0.3 source pipeline against the controlled teaching sample."""

from __future__ import annotations

import asyncio
import argparse
import json
import logging
from pathlib import Path

from vulnagent.bootstrap import build_v03_source_application
from vulnagent.contracts import Target, TargetType
from vulnagent.settings import Settings
from vulnagent.utils.ids import new_target_id


LOGGER = logging.getLogger("vulnagent.demo")


async def run_demo(output: Path | None = None) -> dict[str, object]:
    """Create and run one real source-analysis task through the application."""
    root = Path(__file__).parents[1]
    target_path = root / "samples" / "source_demo"
    services = build_v03_source_application(
        settings=Settings(vulnagent_profile="v03-source")
    )
    task = services.task_manager.create_task(
        Target(
            target_id=new_target_id(),
            path=str(target_path),
            target_type=TargetType.SOURCE,
            language="python",
        )
    )
    context = await services.orchestrator.run(task.task_id)

    LOGGER.info("task_id=%s status=%s", task.task_id, context.task.status.value)
    for finding in context.findings:
        LOGGER.info(
            "candidate=%s cwe=%s status=%s evidence=%d",
            finding.title,
            finding.cwe_id,
            finding.status.value,
            len(finding.evidence_ids),
        )
    for verification in context.verifications:
        LOGGER.info(
            "verification=%s status=%s confidence=%.2f",
            verification.vulnerability_id,
            verification.status.value,
            verification.confidence,
        )
    report = context.reports[-1]
    LOGGER.info(
        "report=%s findings=%d evidence=%d",
        report.artifact_uri,
        report.content["summary"]["finding_count"],
        report.content["summary"]["evidence_count"],
    )
    result: dict[str, object] = {
        "task_id": task.task_id,
        "status": context.task.status.value,
        "target": str(target_path.resolve()),
        "target_executed": False,
        "route_history": context.task.metadata.get("termination", {}).get(
            "route_history", []
        ),
        "findings": [item.model_dump(mode="json") for item in context.findings],
        "verifications": [
            item.model_dump(mode="json") for item in context.verifications
        ],
        "evidence_sources": sorted({item.source for item in context.evidence}),
        "report": report.content,
    }
    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8"
        )
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the canonical source demo.")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    asyncio.run(run_demo(args.output.resolve() if args.output else None))


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    main()
