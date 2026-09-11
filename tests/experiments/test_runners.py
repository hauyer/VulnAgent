"""Small end-to-end checks for the reproducible experiment runners."""

import json
from pathlib import Path

import pytest

from experiments.run_fuzz_ablation import run_suite as run_fuzz_suite
from experiments.run_source_ablation import run_suite as run_source_suite


def _sample(sample_id: str, path: str) -> dict[str, object]:
    return {
        "sample_id": sample_id,
        "family_id": "source-runner-family",
        "difficulty": "hard",
        "path": path,
        "source": "self-authored test",
        "language": "python",
        "target_type": "source",
        "ground_truth": "vulnerable",
        "cwe": ["CWE-95"],
        "expected_findings": ["dynamic_code_execution"],
        "authorization": "local self-authored fixture; controlled execution explicitly allowed",
        "run_command": "pytest",
    }


@pytest.mark.asyncio
async def test_source_ablation_runs_both_real_arms(tmp_path: Path) -> None:
    target = tmp_path / "source-case"
    target.mkdir()
    (target / "app.py").write_text("value = eval(input())\n", encoding="utf-8")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps({"samples": [_sample("source-case", "source-case")]}),
        encoding="utf-8",
    )

    rows = await run_source_suite(manifest, repo_root=tmp_path)

    assert [item["method"] for item in rows] == [
        "vulnagent_verification_off",
        "vulnagent_verification_on",
        "vulnagent_full",
    ]
    assert all(item["observed"] == "vulnerable" for item in rows)
    assert all(item["family_id"] == "source-runner-family" for item in rows)
    assert all(item["difficulty"] == "hard" for item in rows)
    assert rows[0]["confirmed_findings"] == 0
    assert rows[1]["confirmed_findings"] == 1
    assert rows[2]["confirmed_findings"] == 1


@pytest.mark.asyncio
async def test_fuzz_ablation_keeps_equal_budget_and_guidance_wins(
    tmp_path: Path,
) -> None:
    target_dir = tmp_path / "fuzz-case"
    target_dir.mkdir()
    target = target_dir / "target.py"
    target.write_text(
        "import sys\n"
        "def marker():\n    return eval(input())\n"
        "if sys.stdin.buffer.read() == b'VULNAGENT_CODE_MARKER':\n"
        "    raise SystemExit(7)\n",
        encoding="utf-8",
    )
    seeds = target_dir / "seeds"
    seeds.mkdir()
    (seeds / "seed").write_bytes(b"ordinary")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps({"samples": [_sample("fuzz-case", "fuzz-case/target.py")]}),
        encoding="utf-8",
    )

    rows = await run_fuzz_suite(
        manifest,
        repo_root=tmp_path,
        trials=1,
        mutation_count=2,
    )

    by_method = {item["method"]: item for item in rows}
    assert by_method["traditional_random_fuzz"]["attempts"] == 2
    assert by_method["agent_guided_fuzz"]["attempts"] == 2
    assert by_method["traditional_random_fuzz"]["crashes"] == 0
    assert by_method["agent_guided_fuzz"]["crashes"] == 1
    profiles = by_method["agent_guided_fuzz"]["sandbox_profiles"]
    assert profiles
    assert profiles[0]["network_isolation_enforced"] is False
