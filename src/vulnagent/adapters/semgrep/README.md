# Semgrep Adapter

成员 3 维护。将 Semgrep 原始结果转换为 Source Audit 可消费的内部数据；不得直接生成 CONFIRMED 结果。

## 实现状态（V0.5 / P2）

- `adapter.py`：实现 `ToolAdapter` 边界（`health` / `execute` / `capabilities`）。
- 输出统一为 `ToolExecutionResult` + `NormalizedToolFinding` + `ProgramFact`，不越过契约边界。
- 证据映射：`findings_to_evidence()` 输出 `EvidenceV2`，全部带 `independence_group="semgrep"`（同一分析族只算 1 个独立来源）。
- 失败安全：工具缺失 / 超时 / 非 0/1 退出码 / JSON 解析失败均返回 `success=False` 并记录 `metadata.error_kind`，不抛穿管线。
- 可执行文件探测顺序：显式 `executable` → PATH → 当前 venv 的 `Scripts/semgrep.exe` → `python -m semgrep`（semgrep ≥ 1.38 已弃用，仅作兜底）。

## 使用

```python
adapter = SemgrepAdapter()                     # 自动探测 semgrep
health = await adapter.health()                # 版本/可用性
result = await adapter.execute(request)        # ToolExecutionRequest
evidence = adapter.findings_to_evidence(result, task_id=..., session_id=...)
```

## 测试

`tests/adapters/semgrep/test_adapter.py` 覆盖：health（可用/缺失/超时）、execute 失败矩阵（目标缺失/工具缺失/超时/引擎错误退出/JSON 损坏）、成功解析（findings+facts）、证据溯源映射。
