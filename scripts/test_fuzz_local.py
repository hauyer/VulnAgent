import asyncio
from pathlib import Path

from vulnagent.contracts import FuzzRequest
from vulnagent.fuzz.engine import ControlledFuzzEngine


async def main() -> None:
    print("Starting local fuzz test...")

    target = (Path("samples") / "fuzz_demo" / "target.py").resolve()

    seed_dir = (
        Path("samples")
        / "fuzz_demo"
        / "seeds"
    ).resolve()

    print(f"Target: {target}")
    print(f"Seed directory: {seed_dir}")

    if not target.exists():
        print("ERROR: target file does not exist.")
        return

    if not seed_dir.exists():
        print("ERROR: seed directory does not exist.")
        return

    request = FuzzRequest(
        task_id="manual-fuzz-test",
        target_id="local-test-target",
        target_path=str(target),
        authorized=True,
        time_budget_seconds=1,
        metadata={
            "seed_dir": str(seed_dir),
        },
    )

    engine = ControlledFuzzEngine(
        timeout_seconds=1,
        mutation_count=5,
        seed=123,
    )

    print("Running fuzz engine...")

    result = await engine.run(request)

    print()
    print("========== Fuzz Result ==========")
    print(f"executed : {result.executed}")
    print(f"crashes  : {result.crashes}")
    print(f"coverage : {result.coverage}")

    print()
    print("========== Metadata ==========")

    for key, value in result.metadata.items():
        print(f"{key}: {value}")

    print()
    print("========== Evidence ==========")

    print(f"Evidence count: {len(result.evidence)}")

    for item in result.evidence[:10]:
        print(f"- {item.evidence_type}")

    print()
    print("========== Test Finished ==========")


if __name__ == "__main__":
    asyncio.run(main())
