"""Compile and analyze the local binary sample through the canonical runtime."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import shutil
import subprocess
from pathlib import Path

from vulnagent.bootstrap import build_v03_source_application
from vulnagent.contracts import Target, TargetType, TaskStatus
from vulnagent.settings import Settings


LOGGER = logging.getLogger("vulnagent.demo.binary")
ROOT = Path(__file__).resolve().parents[1]


def _build_sample(output: Path) -> Path:
    compiler = shutil.which("gcc") or shutil.which("cc")
    if compiler is None:
        raise RuntimeError("gcc or cc is required to build the binary demo")
    source = ROOT / "samples" / "binary_demo" / "vulnerable.c"
    output.parent.mkdir(parents=True, exist_ok=True)
    completed = subprocess.run(
        [compiler, "-O0", "-fno-builtin", "-s", str(source), "-o", str(output)],
        check=False,
        capture_output=True,
        timeout=30,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.decode(errors="replace")[:2000])
    return output


async def run_demo(target: Path, output: Path) -> dict[str, object]:
    """Run Reverse→Logic/Obfuscation→Verification→Report without execution."""
    services = build_v03_source_application(
        settings=Settings(vulnagent_profile="v03-source")
    )
    task = services.task_manager.create_task(
        Target(
            target_id="binary-demo",
            path=str(target.resolve()),
            target_type=TargetType.BINARY,
            language="c",
        )
    )
    context = await services.orchestrator.run(task.task_id)
    if context.task.status is not TaskStatus.COMPLETED:
        raise RuntimeError(context.task.error or "binary demo did not complete")
    binary_message = next(
        item
        for item in context.messages
        if item.sender == "binary_analysis" and "feature_analysis" in item.payload
    )
    result: dict[str, object] = {
        "task_id": task.task_id,
        "status": context.task.status.value,
        "target": str(target.resolve()),
        "target_executed": False,
        "route_history": context.task.metadata.get("termination", {}).get(
            "route_history", []
        ),
        "findings": [item.model_dump(mode="json") for item in context.findings],
        "verifications": [
            item.model_dump(mode="json") for item in context.verifications
        ],
        "feature_analysis": binary_message.payload["feature_analysis"],
        "evidence_sources": sorted({item.source for item in context.evidence}),
        "report": context.reports[-1].content,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the canonical binary demo.")
    parser.add_argument("--target", type=Path)
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "artifacts" / "demos" / "binary-v03.json",
    )
    args = parser.parse_args()
    target = args.target.resolve() if args.target else _build_sample(
        ROOT / "artifacts" / "demos" / "binary-demo.exe"
    )
    result = asyncio.run(run_demo(target, args.output.resolve()))
    LOGGER.info(
        "status=%s findings=%d output=%s",
        result["status"],
        len(result["findings"]),
        args.output.resolve(),
    )


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    main()
