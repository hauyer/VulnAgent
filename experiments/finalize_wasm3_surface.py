# -*- coding: utf-8 -*-
"""Build the S5 independent-surface finding archive for wasm3:

  artifacts/experiments/p1c-wasm3-surface/

Result-directory contract (roadmap §9): manifest / trace / candidates /
evidence / verification / metrics / checksums / README.  The discovery is a
NULL-pointer-dereference crash (DoS) on malformed wasm modules found by the
independent all-export input surface (the fib-only official driver never
reaches _start).  Frozen via the contracts models; Verification runs the
layered-v1 EvidenceVerifier (the only boundary allowed to write verdicts).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "artifacts" / "experiments" / "p1c-wasm3-surface"
OUT.mkdir(parents=True, exist_ok=True)

CRASH_INPUTS = [
    "0ebffc332ffe892876cfd39e9551a3ac7b39efe7",
    "548cb3313449ffdde21eee3dddd18afa38f3f346",
    "6d6b415c17d515e2684b97ba4a2fbde93815774f",
    "6d987204f4208119dcddb3f865de19c917c8f269",
    "aaea26a7a9626f25e2516976c99e950389fd781c",
]
CORPUS = ROOT / "third_party" / "wasm3" / "fuzz_corpus"

MANIFEST = {
    "experiment": "p1c-wasm3-surface",
    "track": "p1c-external-unknown",
    "title": "wasm3 独立输入面探索（all-export 驱动）：发现 NULL 解引用崩溃族（5 输入，DoS 类）",
    "date": "2026-09-26",
    "protocol": (
        "盲态语料（libFuzzer 学习语料 2232 输入）经独立输入面驱动复扫："
        "枚举模块内全部已定义函数并以类型化默认参数调用（fib-only 官方驱动永不触达的路径）。"
        "发现记录冻结后做判重；Verification 由 layered-v1 独立写入。"
    ),
    "target": {
        "name": "wasm3",
        "upstream": "https://github.com/wasm3/wasm3",
        "license": "MIT",
        "revision": "ea6ad909139a22d224c5d77796421d6ffa91b05f",
        "revision_note": "origin/main HEAD（2026-09-25 提交；= 上游最新）",
        "source_sha256": None,  # filled below
    },
    "driver": {
        "official_surface": "platforms/app_fuzz/fuzzer.c (仅调用导出 fib)",
        "independent_surface": "platforms/app_fuzz/cov_main.c（枚举 module->functions，跳过 import，"
                               "先 CompileFunction 再 m3_Call，类型化默认参数 i32/i64=1、f32/f64=1.0；"
                               "资源上限与官方驱动一致：mem 4MiB / table 1M / gas / cont 256）",
        "compiler": "clang 23.1.2",
        "os": "Windows x86_64",
    },
    "corpus": {
        "dir": "fuzz_corpus",
        "count": 2233,
        "note": "p1c 盲态探索期间 libFuzzer 学习语料（含变异产物）",
        "executed": 2232,
        "rejected": 1,
    },
    "findings": {
        "candidate_count": 1,
        "vulnerability_id": "vuln-wasm3-s001",
        "crash_inputs": CRASH_INPUTS,
        "signature": "调用 _start 时 NULL+0x8 解引用（EXCEPTION_ACCESS_VIOLATION, faultaddr=0x8）",
        "impact_class": "DoS（进程崩溃）；未演示内存破坏",
        "cross_revision": "5848808（2021 漏洞版）/ 8f3986a（2021 修复版）/ ea6ad90（2026 HEAD）均崩溃",
        "novelty_status": "needs_more_evidence",
        "dedup": "无公开 CVE 精确匹配（CVE-2025-15413/15572/6272 为其他函数）；wasm3 已无维护者；"
                 "缺陷类（malformed module -> null deref）在历史 fuzz 记录中常见",
        "disclosure": "not_submitted（候选未人工复核确认前不进入披露讨论）",
    },
    "limitations": [
        "JIT 编译代码内崩溃：ASan 不插桩，无符号化栈帧（根因依据 fault addr 0x8 = IM3Function.import.moduleUtf8 推断）",
        "最小化尝试（1/16/32/64 字节粒度）无法再减：损坏结构为承载性",
        "单宿主/单编译器；未在 Linux 上复现",
        "DoS 类影响；非内存破坏 PoC",
    ],
}

# source tree hash
h = hashlib.sha256()
base = ROOT / "third_party" / "wasm3"
rels = [f"source/{n}" for n in (
    "m3_api_libc.c", "m3_api_libc_wasi_stub.c", "m3_bind.c", "m3_code.c",
    "m3_compile.c", "m3_core.c", "m3_env.c", "m3_exec.c", "m3_function.c",
    "m3_info.c", "m3_module.c", "m3_parse.c")] + ["platforms/app_fuzz/fuzzer.c"]
for rel in sorted(rels):
    p = base / rel
    if p.is_file():
        h.update(rel.encode())
        h.update(p.read_bytes())
MANIFEST["target"]["source_sha256"] = h.hexdigest()

(OUT / "manifest.json").write_text(json.dumps(MANIFEST, ensure_ascii=False, indent=2), encoding="utf-8")


def row_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_candidate_and_evidence() -> tuple[dict, list[dict]]:
    from vulnagent.contracts import Evidence, EvidenceType, VulnerabilityCandidate

    hashes = {n: row_hash(CORPUS / n) for n in CRASH_INPUTS}

    ev1 = Evidence(
        evidence_id="ev-wm3-s001",
        task_id="p1c-wasm3-surface",
        evidence_type=EvidenceType.CRASH_LOG,
        source="wasm3_noseh.exe all <input>：5 个语料输入在调用 _start 时 EXCEPTION_ACCESS_VIOLATION (0xC0000005)，faultaddr=0x8（NULL+8）；无 SEH 时进程硬崩溃（exit=-1073741819）",
        description=(
            "5 个 fuzz 语料输入（272B，损坏导出节被加载器接受）在独立输入面驱动下调用 _start 触发 "
            "NULL 函数引用解引用（fault addr 0x8 = IM3Function.import.moduleUtf8 偏移）。"
            "跨版本复现：5848808 / 8f3986a / ea6ad90 均崩溃。fib-only 官方驱动不复现（不调用 _start）。"
        ),
        artifact_path="third_party/wasm3/fuzz_corpus/*",
        data={
            "crash_inputs": {n[:12]: {"size": (CORPUS / n).stat().st_size, "sha256": hashes[n]} for n in CRASH_INPUTS},
            "fault_addr": "0x8",
            "exception_code": "0xC0000005",
            "hard_crash_exit": "-1073741819",
            "replay_runs": 5,
            "cross_revisions": {"5848808": "crash", "8f3986a": "crash", "ea6ad90": "crash"},
            "minimization": "1/16/32/64-byte 粒度无缩减（272B 保持）",
        },
        reliability=0.97,
        created_by="IndependentSurfaceRunner(p1c-wasm3-surface)",
    )

    ev2 = Evidence(
        evidence_id="ev-wm3-s002",
        task_id="p1c-wasm3-surface",
        evidence_type=EvidenceType.TOOL_RESULT,
        source="判重检索（2026-09-26，NVD/CVE.org/Snyk/SentinelOne）",
        description=(
            "wasm3 公开记录：CVE-2025-15413（op_SetSlot_i32/op_CallIndirect 内存破坏）、"
            "CVE-2025-15572（NewCodePage 内存泄漏）、CVE-2025-6272（MarkSlotAllocated OOB 写）"
            "均为不同函数/根因；未见与本路径（损坏导出节模块 → _start NULL 解引用）精确匹配的公开 CVE。"
            "项目自 2022 年后无活跃维护者。缺陷类在 BlackHat-22 wasm3 fuzz 综述中列为常见。"
        ),
        artifact_path="",
        data={
            "public_cves_checked": ["CVE-2025-15413", "CVE-2025-15572", "CVE-2025-6272", "CVE-2021-38592"],
            "matching_record": None,
            "novelty_status": "needs_more_evidence",
        },
        reliability=0.9,
        created_by="ResearchRecord(p1c-wasm3-surface)",
    )

    ev3 = Evidence(
        evidence_id="ev-wm3-s003",
        task_id="p1c-wasm3-surface",
        evidence_type=EvidenceType.SOURCE_LOCATION,
        source="m3_exec.h op_Call / op_CallIndirect 区域：对 IM3Function 无 NULL 守卫即解引用字段",
        description=(
            "fault addr 0x8 与 IM3Function.import.moduleUtf8（结构体偏移 8）一致：执行路径解引用 NULL 函数引用。"
            "wasm3 对未解析/空函数引用未以 trap 终止而是直接解引用（推断，JIT 代码无法符号化）。"
        ),
        artifact_path="third_party/wasm3/source/m3_exec.h",
        data={"functions": ["op_Call", "op_CallIndirect"], "fault_offset_hypothesis": 8, "cwe": "CWE-476"},
        reliability=0.8,
        created_by="Reviewer(p1c-wasm3-surface)",
    )

    candidate = VulnerabilityCandidate(
        vulnerability_id="vuln-wasm3-s001",
        task_id="p1c-wasm3-surface",
        title="wasm3: 损坏导出节模块调用 _start 时 NULL 函数引用解引用导致进程崩溃",
        vulnerability_type="NULL pointer dereference (crash / DoS)",
        cwe_id="CWE-476",
        description=(
            "libFuzzer 变异语料中的 5 个 272B 模块（导出节损坏但被 m3_ParseModule/m3_LoadModule 接受）"
            "在调用 _start 时触发 EXCEPTION_ACCESS_VIOLATION（faultaddr=0x8），进程硬崩溃；"
            "5848808/8f3986a/ea6ad90 三版本均复现。独立输入面（枚举全部已定义函数）首次触达；"
            "官方 fib-only 驱动不复现。DoS 类影响；判重未见公开精确匹配（needs_more_evidence）。"
        ),
        target_id="wasm3@ea6ad90",
        location={
            "file_path": "third_party/wasm3/source/m3_exec.h",
            "function_name": "op_Call/op_CallIndirect (inferred)",
            "line_start": None,
            "line_end": None,
            "binary_address": None,
            "module_name": "wasm3",
        },
        source_agent="IndependentSurfaceRunner(p1c-wasm3-surface)",
        source_type="dynamic_fuzz",
        producer="clang 23.1.2 + 独立输入面驱动",
        confidence=0.8,
        severity="medium",
        evidence_ids=["ev-wm3-s001", "ev-wm3-s002", "ev-wm3-s003"],
        status="verifying",
        metadata={
            "novelty_status": "needs_more_evidence",
            "impact_class": "DoS",
            "practice_mode": False,
            "disclosure": "not_submitted",
        },
    )
    return candidate, [ev1, ev2, ev3]


async def main() -> None:
    from vulnagent.contracts import VerificationContext
    from vulnagent.verification.evidence_verifier import EvidenceVerifier

    candidate, evidence = build_candidate_and_evidence()

    (OUT / "candidates.jsonl").write_text(
        candidate.model_dump_json() + "\n", encoding="utf-8"
    )
    (OUT / "evidence.jsonl").write_text(
        "\n".join(e.model_dump_json() for e in evidence) + "\n", encoding="utf-8"
    )

    verifier = EvidenceVerifier(strategy_version="layered-v1")
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
    (OUT / "verification.jsonl").write_text(json.dumps(record, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"verdict: {result.status.value} conf={result.confidence:.2f} layers={result.metadata.get('layers')}")

    metrics = {
        "run_id": "p1c-wasm3-surface",
        "executions": 2232,
        "rejected": 1,
        "hard_crashes": 5,
        "unique_crash_inputs": 5,
        "crash_signature": "NULL+0x8 deref in _start",
        "timeouts": 0,
        "oom": 0,
        "candidates": 1,
        "outcome": "positive_candidate_dos",
        "verification": {"status": record["status"], "confidence": record["confidence"]},
    }
    (OUT / "metrics.json").write_text(json.dumps(metrics, ensure_ascii=False, indent=2), encoding="utf-8")

    (OUT / "trace.jsonl").write_text(
        json.dumps({"event": "independent-surface-corpus-scan", "mode": "all",
                    "inputs": 2232, "crashes": 5}, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    (OUT / "checksums.sha256").write_text(
        "\n".join(
            f"{hashlib.sha256((OUT / f).read_bytes()).hexdigest()}  {f}"
            for f in ("manifest.json", "trace.jsonl", "candidates.jsonl",
                      "evidence.jsonl", "verification.jsonl", "metrics.json")
        ) + "\n",
        encoding="ascii",
    )

    (OUT / "README.md").write_text(
        """# P1-C wasm3 独立输入面探索（阳性候选：NULL 解引用 DoS）

- 生成：`experiments/finalize_wasm3_surface.py`；复现：`third_party/wasm3/platforms/app_fuzz/wasm3_noseh.exe all <input>`
- 崩溃输入（third_party/wasm3/fuzz_corpus/）：0ebffc33 / 548cb331 / 6d6b415c / 6d987204 / aaea26a7（272B，哈希见 evidence.jsonl）
- 驱动：cov_main.c all 模式（枚举全部已定义函数，类型化默认参数；官方 fib 驱动不复现）
- 跨版本：5848808 / 8f3986a / ea6ad90 均崩溃；上游 origin/main（2026-09-25）未修复
- 判重：无公开 CVE 精确匹配 → needs_more_evidence；未申报披露
- 依赖：clang 23.1.2；Windows x86_64
""",
        encoding="utf-8",
    )
    print("archive written:", OUT)


if __name__ == "__main__":
    asyncio.run(main())
