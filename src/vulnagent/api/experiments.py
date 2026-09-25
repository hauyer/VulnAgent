"""WP7: read-only research API for experiment artifacts.

Serves ``summary.json`` / ``metrics.json`` produced by the experiment
scripts (WP4 dynamic loop, WP5 blind evaluation, WP6 exploration) so the UI
can show real recorded facts without re-running anything and without building
parallel state. Read-only and path-whitelisted: experiment ids are restricted
to ``[a-z0-9_-]`` and only files under ``artifacts/experiments/`` are served.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from fastapi import APIRouter, HTTPException

router = APIRouter()

_ID_RE = re.compile(r"^[a-z0-9_-]+$")
_EXPERIMENTS_ROOT = Path(__file__).resolve().parents[3] / "artifacts" / "experiments"


def _list_experiments() -> list[str]:
    if not _EXPERIMENTS_ROOT.is_dir():
        return []
    return sorted(
        p.name
        for p in _EXPERIMENTS_ROOT.iterdir()
        if p.is_dir() and _ID_RE.fullmatch(p.name)
    )


@router.get("/experiments")
async def list_experiments() -> dict:
    return {"experiments": _list_experiments()}


@router.get("/experiments/{experiment_id}")
async def experiment_detail(experiment_id: str) -> dict:
    if not _ID_RE.fullmatch(experiment_id):
        raise HTTPException(status_code=404, detail="experiment not found")
    root = _EXPERIMENTS_ROOT / experiment_id
    if not root.is_dir():
        raise HTTPException(status_code=404, detail="experiment not found")

    payload: dict = {"experiment_id": experiment_id}
    summary_path = root / "summary.json"
    if summary_path.is_file():
        try:
            payload["summary"] = json.loads(summary_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            payload["summary_error"] = "summary.json is not valid JSON"
    metrics_path = root / "metrics.json"
    if metrics_path.is_file():
        try:
            payload["metrics"] = json.loads(metrics_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            payload["metrics_error"] = "metrics.json is not valid JSON"

    candidates_path = root / "candidates.jsonl"
    if candidates_path.is_file():
        payload["candidate_count"] = sum(
            1 for _ in candidates_path.read_text(encoding="utf-8").splitlines()
        )
    return payload
