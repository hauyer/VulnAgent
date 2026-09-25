# WP3 — 证据缺口驱动的 Planner（EvidenceGapPlanner）

## 目标（开发指导书 8.2）

把 V0.2「固定顺序调用」的路由升级为**证据缺口驱动**：由 `EvidenceGapPlanner`
根据当前候选与证据的缺口，产出受控的动作计划；Supervisor 只负责把计划翻译成
经过预算/权限/循环校验的合法路由。LLM 只能建议动作，不能绕过 ToolRegistry。

## 新增模块

- `src/vulnagent/agent_runtime/evidence_gap.py`
  - `EvidenceGapKind`：`target_blocked / missing_location / missing_call_path /
    unknown_guard / engine_disagreement / fuzz_ready / missing_fixed_contrast /
    evidence_sufficient / insufficient_evidence`
  - `PlannedAction`：`stop_blocked / stop_uncertain / parse_or_index /
    guard_recheck / independent_review / bounded_fuzz / verification`
  - `ActionBinding`：每个动作绑定 `permission_required / budget_seconds /
    expected_evidence / failure_fallback`
  - `EvidenceGapPlanner.plan(task, context) -> PlanDecision`

### 确定性规则链（严格顺序）

1. 目标未准入 → `STOP_BLOCKED`（`metadata.admitted != True`）
2. 无候选 → `PARSE_OR_INDEX`（权限 `static_read`，回退 `STOP_UNCERTAIN`）
3. 候选无具体 `location` → `PARSE_OR_INDEX`
4. 候选有 sink 但无 `CALL_PATH/DATA_FLOW` 证据 → `GUARD_RECHECK`（`missing_call_path`）
5. 候选无 guard 事实 → `GUARD_RECHECK`（`unknown_guard`）
6. 多 provider 引擎对同一候选结论不一致 → `INDEPENDENT_REVIEW`
7. 动态授权且存在可测 entry point → `BOUNDED_FUZZ`（权限 `dynamic_run`，回退 `GUARD_RECHECK`）
8. 未对比修复版本 → `GUARD_RECHECK`（`missing_fixed_contrast`）
9. 候选已有 ≥1 条自有证据 → `VERIFICATION`
10. 其余 → `STOP_UNCERTAIN`

## Supervisor 组合接入

- `Supervisor.__init__(..., gap_planner=None)`：注入后启用 WP3 路由；
  `None` 时保持 V0.2 固定顺序（向后兼容）。
- `decide()` 在 `current == SOURCE_ANALYSIS` 且注入 planner 时走
  `_route_by_evidence_gap(task, context, history)`。
- **有界回退（关键修复）**：`GUARD_RECHECK / PARSE_OR_INDEX` 若 SOURCE_ANALYSIS
  已执行过（`history.count >= 1`），不再重跑同一引擎（无新增证据且会造成候选翻倍），
  回退 `_legacy_after_analysis`：`findings 空 → REPORT`；`fuzz_requested 且 FUZZ
  未跑 → FUZZ`；否则 `VERIFICATION`。缺口信息写入路由 `metadata.gap_kind / plan`。
- `BOUNDED_FUZZ`：`FUZZ` 已在 history → 直接 `VERIFICATION`；否则路由 `FUZZ`
  并携带 `budget_seconds / permission_required`。
- `STOP_BLOCKED → FINISH`；`STOP_UNCERTAIN → REPORT`；`INDEPENDENT_REVIEW → REVIEWER`。

## 组装（bootstrap）

- `build_application(..., gap_planner=None)` 注入 `Supervisor`。
- `build_v03_source_application(gap_planner=None)`：**默认启用**
  `EvidenceGapPlanner()`；显式传 `None` 可关闭。
- `build_mock_application()`：不启用（V0.2 mock 语义不变）。

## 测试

- `tests/unit/test_evidence_gap_planner.py`（21 项）：
  - 规则链每一条分支（blocked / parse / missing path / unknown guard /
    disagreement / fuzz 授权与未授权 / fixed contrast / sufficient /
    uncertain / 确定性）
  - Supervisor 路由翻译：blocked→FINISH、gap→VERIFICATION（带 metadata）、
    fuzz→FUZZ（预算/权限 metadata）、fuzz 已跑→VERIFICATION、
    无 planner 保持 legacy 顺序。

## 验证结果

- WP3 新增单测：21/21 通过。
- 全量门禁：**714 passed / 1 skipped**（基线 693 + 21，0 回归）。
- 修复过程中发现并解决：gap planner 默认启用会改变 v03-source 真实链路的
  路由行为（`test_real_source_end_to_end` 候选翻倍、`test_real_fuzz_end_to_end`
  跳过 fuzz）→ 以「同一引擎不重跑、缺口交验证/已请求 fuzz」的有界回退解决，
  并保留缺口追踪 metadata。

## 限制与说明

- `INDEPENDENT_REVIEW` 目前路由到 REVIEWER（复核），复核后按现有顺序进 REPORT；
  引擎分歧的最终裁决语义（CONFIRMED/REJECTED 唯一写入者仍是 Verification）不变。
- fuzz 授权位读取 `target.metadata.fuzz_authorized / dynamic_allowed`，
  与 WP0 准入框架的四维授权模型一致。
- LLM 不参与路由决策：本工作包是确定性规则 + 显式预算，模型仅通过
  `context.messages` 的 plan 消息建议能力，最终路由由 Supervisor 校验。
