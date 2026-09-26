"""WP7/S6: read-only research API for experiment artifacts.

Serves ``manifest.json`` / ``metrics.json`` / ``candidates.jsonl`` /
``evidence.jsonl`` / ``clusters.jsonl`` / ``verification.jsonl`` produced by
the experiment scripts so the UI can show real recorded facts without
re-running anything and without building parallel state.  Read-only and
path-whitelisted: experiment ids are restricted to ``[a-z0-9_-]`` and only
files under ``artifacts/experiments/`` are served.

S6 additions (roadmap work-package F):
  * detail response now carries manifest digest (protocol / target revision /
    source hash / budget / status / isolation capability / error reason) and
    an explicit metrics state (``ready`` / ``pending``).
  * ``GET /experiments/{id}/findings``: read-only findings list with status
    filter + pagination; candidate id, nullable CWE, evidence ids, verification
    status and root-cause cluster id.
  * ``GET /experiments/{id}/metrics``: three denominators (case / candidate /
    unique-root-cause), TP/FP/FN, undefined reasons and unavailable counts;
    only opened once the scoring process has finalized metrics.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from fastapi import APIRouter, Query

from vulnagent.api.errors import bad_request, not_found

router = APIRouter()

_ID_RE = re.compile(r"^[a-z0-9_-]+$")
_EXPERIMENTS_ROOT = Path(__file__).resolve().parents[3] / "artifacts" / "experiments"


def _read_jsonl(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    rows: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def _read_json(path: Path) -> dict | None:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


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


def _resolve(experiment_id: str) -> Path:
    if not _ID_RE.fullmatch(experiment_id):
        raise not_found("experiment not found")
    root = _EXPERIMENTS_ROOT / experiment_id
    if not root.is_dir():
        raise not_found("experiment not found")
    return root


@router.get("/experiments/{experiment_id}")
async def experiment_detail(experiment_id: str) -> dict:
    root = _resolve(experiment_id)

    payload: dict = {"experiment_id": experiment_id}
    summary_path = root / "summary.json"
    if summary_path.is_file():
        summary = _read_json(summary_path)
        if summary is None:
            payload["summary_error"] = "summary.json is not valid JSON"
        else:
            payload["summary"] = summary
    metrics_path = root / "metrics.json"
    metrics = _read_json(metrics_path)
    if metrics_path.is_file() and metrics is None:
        payload["metrics_error"] = "metrics.json is not valid JSON"

    manifest = _read_json(root / "manifest.json")
    payload["metrics_state"] = "ready" if _metrics_finalized(manifest, metrics) else "pending"
    if manifest is not None:
        payload["manifest"] = _manifest_digest(manifest)
    elif (root / "manifest.json").exists():
        payload["manifest_error"] = "manifest.json is not valid JSON"

    candidates_path = root / "candidates.jsonl"
    if candidates_path.is_file():
        payload["candidate_count"] = sum(
            1 for _ in candidates_path.read_text(encoding="utf-8").splitlines()
        )
    verification_path = root / "verification.jsonl"
    if verification_path.is_file():
        payload["verification_count"] = sum(
            1 for _ in verification_path.read_text(encoding="utf-8").splitlines()
        )
    clusters_path = root / "clusters.jsonl"
    if clusters_path.is_file():
        payload["cluster_count"] = sum(
            1 for _ in clusters_path.read_text(encoding="utf-8").splitlines()
        )
    return payload


def _metrics_finalized(manifest: dict | None, metrics: dict | None) -> bool:
    if metrics is None:
        return False
    if metrics.get("finalized") is True or metrics.get("status") == "finalized":
        return True
    if manifest is not None and manifest.get("metrics_finalized") is True:
        return True
    # A metrics file that already carries verdict numbers is treated as final.
    return "precision" in metrics or "tp" in metrics or "tp_count" in metrics


def _manifest_digest(manifest: dict) -> dict:
    target = manifest.get("target") or {}
    return {
        "protocol": manifest.get("protocol") or manifest.get("track"),
        "status": manifest.get("status") or manifest.get("outcome"),
        "target_revision": target.get("revision") or target.get("fixed_revision"),
        "source_sha256": target.get("source_sha256"),
        "upstream": target.get("upstream"),
        "license": target.get("license"),
        "budget": manifest.get("budget") or manifest.get("runs"),
        "isolation": manifest.get("isolation") or "single-host sandbox",
        "error_reason": manifest.get("error_reason"),
    }


@router.get("/experiments/{experiment_id}/findings")
async def experiment_findings(
    experiment_id: str,
    status: str | None = Query(default=None, description="filter by verification status"),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=500),
) -> dict:
    """Read-only findings list: candidates joined with verification + clusters.

    Never exposes ground truth: only candidate rows already frozen on disk are
    returned; verification status comes from ``verification.jsonl`` (written by
    the Verification boundary alone) or stays ``verifying``.
    """
    root = _resolve(experiment_id)
    candidates = _read_jsonl(root / "candidates.jsonl")
    verifications = {r.get("vulnerability_id"): r for r in _read_jsonl(root / "verification.jsonl")}
    clusters = _read_jsonl(root / "clusters.jsonl")
    cluster_by_candidate: dict[str, str] = {}
    for row in clusters:
        cid = row.get("candidate_id") or row.get("vulnerability_id")
        if cid:
            cluster_by_candidate[cid] = str(row.get("cluster_id") or row.get("root_cause_cluster_id") or "")

    findings: list[dict] = []
    for row in candidates:
        candidate_id = str(row.get("vulnerability_id") or row.get("candidate_id") or "")
        ver = verifications.get(candidate_id) or {}
        ver_status = str(ver.get("status") or row.get("status") or "verifying")
        if status and ver_status.lower() != status.lower():
            continue
        findings.append(
            {
                "candidate_id": candidate_id,
                "cwe_id": row.get("cwe_id") or None,
                "evidence_ids": list(row.get("evidence_ids") or []),
                "verification_status": ver_status,
                "verification_confidence": ver.get("confidence"),
                "root_cause_cluster_id": cluster_by_candidate.get(candidate_id) or None,
                "severity": row.get("severity"),
                "novelty_status": (row.get("metadata") or {}).get("novelty_status"),
            }
        )

    total = len(findings)
    page = findings[offset : offset + limit]
    return {
        "experiment_id": experiment_id,
        "total": total,
        "offset": offset,
        "limit": limit,
        "findings": page,
    }


@router.get("/experiments/{experiment_id}/metrics")
async def experiment_metrics(
    experiment_id: str,
    metrics_version: str | None = Query(default=None),
) -> dict:
    """Three-denominator metrics view, opened only after scoring finalized.

    ``case`` / ``candidate`` / ``unique-root-cause`` denominators, TP/FP/FN,
    undefined reasons and unavailable counts are recomputed from frozen files
    where possible; before scoring completes the response is an explicit
    ``pending`` state instead of a partial answer.
    """
    root = _resolve(experiment_id)
    manifest = _read_json(root / "manifest.json")
    metrics = _read_json(root / "metrics.json")

    if not _metrics_finalized(manifest, metrics):
        return {
            "experiment_id": experiment_id,
            "metrics_state": "pending",
            "message": "scoring process not finalized; metrics not yet open",
        }
    if metrics_version is not None and metrics.get("metrics_version") != metrics_version:
        raise bad_request(f"metrics version {metrics_version} not found")

    candidates = _read_jsonl(root / "candidates.jsonl")
    clusters = _read_jsonl(root / "clusters.jsonl")
    case_count = _case_count(manifest, metrics)
    candidate_count = len(candidates)
    root_cause_count = _root_cause_count(clusters, candidates)

    def num(*keys: str) -> int | None:
        for key in keys:
            v = metrics.get(key)
            if isinstance(v, (int, float)):
                return int(v)
        return None

    return {
        "experiment_id": experiment_id,
        "metrics_state": "ready",
        "metrics_version": metrics.get("metrics_version"),
        "denominators": {
            "case": case_count,
            "candidate": candidate_count,
            "unique_root_cause": root_cause_count,
        },
        "verdicts": {
            "tp": num("tp", "tp_count", "true_positives"),
            "fp": num("fp", "fp_count", "false_positives"),
            "fn": num("fn", "fn_count", "false_negatives"),
            "tn": num("tn", "tn_count", "true_negatives"),
        },
        "precision": metrics.get("precision"),
        "recall": metrics.get("recall"),
        "undefined_reasons": metrics.get("undefined_reasons") or metrics.get("undefined"),
        "unavailable": {
            "tools": metrics.get("tools_unavailable") or metrics.get("unavailable_tools"),
            "runs": metrics.get("runs_unavailable") or metrics.get("unavailable_runs"),
        },
        "raw_metrics_present": metrics is not None,
    }


def _case_count(manifest: dict | None, metrics: dict | None) -> int | None:
    if metrics:
        for key in ("total_cases", "case_total", "cases"):
            v = metrics.get(key)
            if isinstance(v, (int, float)):
                return int(v)
    if manifest:
        for key in ("case_count", "total_cases", "target_count"):
            v = manifest.get(key)
            if isinstance(v, (int, float)):
                return int(v)
    return None


def _root_cause_count(clusters: list[dict], candidates: list[dict]) -> int | None:
    unique = {str(c.get("cluster_id") or c.get("root_cause_cluster_id")) for c in clusters}
    unique.discard("None")
    unique.discard("")
    if unique:
        return len(unique)
    for c in candidates:
        meta = c.get("metadata") or {}
        cl = meta.get("root_cause_cluster_id")
        if cl:
            unique.add(str(cl))
    if unique:
        return len(unique)
    return None if candidates else 0
