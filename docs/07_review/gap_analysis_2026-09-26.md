# VulnAgent 与开发文档差距分析（2026-09-26）

> 对照基线：《VulnAgent_高分开发与验收路线图_2026-09-26.md》（下称"路线图"）§2/§3/§9 与 AGENTS.md。
> 方法：逐项核对磁盘上的代码、OpenAPI 路由、实验档案与测试（`python -m pytest --ignore=tests/system` = 864 collected / 862 passed / 2 skipped，2026-09-26 实测）。
> 口径：本文只陈述"已实现 / 部分实现 / 未实现"，不把原型、自编样本或历史负结果包装成已达标能力。
> **2026-09-26 同日更新**：路线图 §2.1/§3.1 全部采用项与 §9 完成门槛已落地（L1/L3/L4/L5/L7/L8/L9/L10、archive_verifier、manifest 引用与 run_id），原差距表保留为基线对照，新增 §7 记录本轮关闭情况；全量回归升至 **862 passed / 2 skipped**。

## 0. 结论总览

| 维度 | 总体状态 | 最大差距 |
|---|---|---|
| 接口（§9 工作包 F） | **已完成**：findings/metrics/trace 增强/错误信封/协议校验/run_id/run 目录校验全部落地并有测试 | 无（SSE 为文档条件项，未要求） |
| 能力（§3.1 逻辑接口） | 发现链路（盲态 runner/评测/泄漏守卫）完整；复核与判重完整；**§3.1 A–E 拟新增接口全部实现** | 无（ContextSliceProvider 已接入 CodeAuditAgent 主链） |
| 同类产品引用（§2.1 L1–L12） | **采用项全部落地**：L10✅ L6✅ L1✅ L3✅ L5✅ L7✅ L8(有限)✅ L9✅；L4 按决定完成 ReproductionComparator；L11 部分（网络/文件隔离如实标 unsupported）；L2 已覆盖；L12 按决定暂缓 | 无未落地采用项 |
| 自主找漏洞能力 | 全链路真实可复现；**盲态自动命中真实漏洞 = 0（TP=0）**；最接近真实的阳性是 wasm3 独立面 5 崩溃输入（needs_more_evidence，未人工复核） | 无一条"盲态自动发现"命中已知或未知漏洞；wasm3 surface 候选是**种子驱动重放**产出，不能宣称 0-day |

## 1. 接口差距（对照路线图 §9 路由表）

| 路由 | 文档要求 | 现状 | 差距 |
|---|---|---|---|
| `POST /api/tasks` | 扩展准入；`metadata` 引用 `target_manifest_id` 与实验协议 | 有 software_code 审计准入（local_authorized/defensive_only/拒远程路径） | **未接 target_manifest_id/实验协议引用** |
| `POST /api/tasks/{task_id}/run` | 既有 Task 状态，`metadata.run_id` 供查实验记录 | 运行并返回 Task | **未写 run_id 到 metadata** |
| `GET /api/tasks/{task_id}/trace` | 增强：路由原因/证据 ID/运行摘要；脱敏；不返回 GT | ✅ detail=true 脱敏+summary+`ground_truth_included=False`；默认向后兼容 | 无 |
| `GET /api/experiments/{experiment_id}` | manifest/指标/目标哈希/隔离能力/预算/错误原因；pending | ✅ manifest 摘要 + metrics_state + verification/cluster 计数 | 无 |
| `GET /api/experiments/{id}/findings` | 状态过滤/分页/CWE 可空/证据 ID/复核状态/根因簇 | ✅ 已实现+测试 | 无 |
| `GET /api/experiments/{id}/metrics` | 三分母/TP/FP/FN/undefined/不可用；评分后开放 | ✅ 已实现（pending→ready）+测试 | 无 |
| `GET /api/dossiers/{session_id}/redacted` | 脱敏材料与真实/模拟状态 | ✅ 已有 | 无 |
| 错误信封 | code/message/run_id?/retryable/detail_ref?；7 个建议错误码 | ✅ 9 个错误码 + 全局 handler + 兼容 detail | 无 |
| 结果目录校验 | 从 run_id 可追溯；删除/篡改校验失败；发现端点读不到 GT | 档案齐全（manifest/trace/candidates/evidence/verification/metrics/checksums）；**clusters.jsonl 仅部分档案有** | **无 run 目录校验脚本**；clusters 未统一 |

## 2. 能力差距（对照路线图 §3.1 逻辑接口）

| 接口 | 文档要求 | 现状 | 差距 |
|---|---|---|---|
| Target admission | 目标来源/许可/修订/哈希/授权/执行策略 → admitted/blocked+原因 | `intake/validator.py`+loader+hashing 存在（基础准入） | ✅ 基础版已满足；未扩展 TargetProfile |
| TargetProfiler（§3.1 A） | 目标画像 + Supervisor 能力路由建议 | `intake/profile.py` **不存在** | ❌ 未实现 |
| BoundedTargetExecutor / DiscoveryPolicy（§3.1 C） | 受控执行端口、隔离能力上报 | `benchmark/discovery_ports.py` ✅ 已实现（S1） | 无 |
| Blind runner | agent-visible manifest、固定预算、绝不传 GT | `runner.py` 重写 ✅（BlindDiscoveryRunner + Generic 策略，无目标专属标签） | 无 |
| Evaluator | TP/FP/FN、不可用、分母、匹配依据；dataset 来自 manifest | `evaluator.py` 重写 ✅（聚类、全分母、strict/relaxed、match_basis=none） | 无 |
| Evidence aware verification（§3.1 D） | 三层证据 + guard 语义 + 版本化策略 | `evidence_verifier.py` layered-v1 ✅（observed_fault/root_cause_supported/security_impact_supported） | 无 |
| ContextSliceProvider（§3.1 B / L1） | 按需跨文件证据切片，接入 SourceAuditAgent | 类已实现 + 单测（S3） | **未接入 bootstrap/Supervisor/Agent 主链** |
| BudgetedLLM（§3.1 E / L5） | 按 run/Agent 计量、预估拦截、usage 对账、超预算结构化降级 | `llm/budget.py` **不存在**；`generate_with_usage` 仅返回 usage 结构，无跨 run 累计/停止 | ❌ 未实现 |
| UntrustedExcerpt（§3.1 E / L10） | 不可信输入来源标记/长度限制/脱敏；工具调用经 allowlist | `llm/untrusted_input.py` **不存在** | ❌ 未实现（优先采用顺序第 1） |
| Disclosure dossier | 草稿/已联系/已报送真实状态、脱敏 | `review/dossier.py`+`api/dossiers.py` ✅ | 无 |
| Dedup（S5） | novelty_unknown/known_duplicate/false_positive/needs_more_evidence | `review/triage.py` DedupClassifier ✅ + 7 测试 | 无 |
| Agent Runtime 接入 | 真实 Agent trace、路由原因、步数上限 | `agent_run.py`+Supervisor+7 Agent 注册 ✅ | 无 |

## 3. 同类产品优点引用落地（对照路线图 §2.1 L1–L12）

| 项 | 处理决定 | 落地状态 |
|---|---|---|
| L1 Vulnhuntr 上下文切片 | 采用 | **部分**：ContextSliceProvider 实现+单测，未接入主链 |
| L2 PentestGPT 分工 | 有限采用 | ✅ 已有 Supervisor+libFuzzer 结构化解析，无需新增 |
| L3 ATLANTIS 能力路由 | 采用（TargetProfile） | ❌ 未实现 |
| L4 patch 后重编译 | 暂缓（ReproductionComparator） | ❌ 未实现（S2 以手动双版本对照替代，可接受） |
| L5 分 Agent 预算 | 采用（BudgetedLLM） | ❌ 未实现 |
| L6 无 PoV 不上报 | 采用证据分层 | ✅ layered-v1 已落地 |
| L7 已知问题引导变体 | 采用独立 track | ❌ 未实现（VariantHypothesis 不存在） |
| L8 fuzz 反馈闭环 | 有限采用（SeedProposalProvider） | ❌ 未实现 |
| L9 CAI handoff | 有限采用 | ✅ AgentMessage/Supervisor 已满足 |
| L10 提示注入防护 | 采用（排第 1） | ❌ 未实现（untrusted_input.py 不存在） |
| L11 资源隔离/二次裁决 | 采用能力声明 | **部分**：Job Object 资源限制 ✅；网络/文件隔离如实标 unsupported；Reviewer 不写状态 ✅ |
| L12 有向 fuzz | 暂缓 | 符合决定（未做） |

采用优先顺序落地率：L10 ❌ → L6 ✅ → L1 部分 → L3 ❌ → L5 ❌ → L7 ❌。

## 4. 自主找漏洞能力（真实证据与诚实结论）

### 4.1 已实现的能力链路（全部真实可复现）

```
盲态 runner（无标签 spec/固定预算/泄漏守卫）→ 真实 Agent（BlindBinaryObserver/BlindDiscovery）
→ 候选（CWE 可空、location 仅来自符号化栈）→ layered-v1 独立 Verification
→ 冻结 JSONL/checksums → 独立 Evaluator（GT 隔离）→ DedupClassifier 判重 → Dossier 披露状态机
```

### 4.2 各层级发现结果

| 层级 | 目标 | 执行 | 结果 | 定性 |
|---|---|---|---|---|
| L2 盲态基准 | QuickJS（CVE-2023-48183） | 240 次 | 2 候选；**tp=0 fp=2 fn=1** | 诚实负结果（盲态未重发现已知 CVE） |
| L2 盲态基准 | wasm3（CVE-2021-38592） | 240 次 | 1 候选；**tp=0 fp=1 fn=1** | 诚实负结果 |
| L3 外部未知 | mujs | ≈28.2 万次 | 0 崩溃 | 负结果（函数覆盖 31.66%） |
| L3 外部未知 | wasm3 官方面 | ≈596 万次 | 0 崩溃 | 负结果（fib 覆盖 46.53%） |
| L3 外部未知 | **wasm3 独立面** | 2232 语料重放 | **5 个崩溃输入**（NULL+0x8，跨 3 版本全崩溃）→ 1 候选 CONFIRMED 0.95 | **needs_more_evidence**；种子驱动重放，非盲态 fuzz 产出 |
| L3 外部未知 | microtar | 手工种子 | 1 候选 | **known_duplicate**（公开 CVE 族） |
| L0 教学演练 | fuzz-kv-store / slot-table | 自编目标 | 2 候选 | 不能冒充真实发现 |

### 4.3 诚实结论

1. **盲态自动发现命中真实漏洞：目前 0 命中（所有盲态 run 的 TP=0）**。链路真实、隔离真实、评分真实，但发现能力尚未在基准集上"抓到"已知漏洞。
2. **最接近真实的阳性候选**是 wasm3 独立输入面的 5 个崩溃输入：可复现、跨版本、最小化 272B、无公开 CVE 精确匹配——但它是**语料重放暴露**而非盲态变异自动生成，且未人工复核，因此只能定性 `needs_more_evidence`，**不能宣称 0-day**。
3. microtar 是公开漏洞族重发现（known_duplicate），不进入新漏洞计数。
4. 国家漏洞库（课件④）：**流程就绪、实际未提交**——这是正确且必须保持的真实状态。
5. 与路线图 §1"当前可说的结论"一致：没有任何一处把负结果、种子重放或自编样本包装成正发现。

## 5. 门禁状态核对（A–E）

| 门禁 | 判据 | 现状 |
|---|---|---|
| A（两条已知 CVE 动态复现） | ≥2 条真实案例可重建、有修复对照与原理边界 | ✅ QuickJS + wasm3 双版本 ASan 动态复现/修复对照；GPAC/libxml2 为 static_only |
| B（盲态发现可复现） | ≥2 不同来源 case build+blind-run+independent-evaluate；≥2 真实 Agent trace；GT 泄漏守卫；分母完整 | ✅ S1/S2 达成（810 tests 含泄漏守卫与评测测试） |
| C（外部目标探索） | 干净环境可重跑；阴性有执行次数/覆盖限制；阳性有哈希/重放/根因/判重/独立复核 | ✅ S5 达成（mujs/wasm3 负结果 + wasm3-surface 阳性建档 + microtar 审查卡 + DedupClassifier） |
| D（误报抑制与消融） | 五臂指标可从原始行重算；有"修正前 FP→修正后不确认"案例 | ✅ wp8-ablation 修正口径后全分母、有 corrected 指标；反例/持出集语义已在路线图 §7 记录 |
| E（披露） | 状态/回执一致；无真实回执不显示已提交 | ✅ 流程就绪、实际未提交（正确状态） |

## 6. 建议的差距关闭顺序（按路线图优先采用顺序）

1. **L10 提示注入防护**（`llm/untrusted_input.py`）——最高优先：目标源码/日志/网页摘录进入 Prompt 是当前真实存在的不可信数据边界；配合工具 allowlist 测试。
2. **ContextSliceProvider 接入主链**——类已写好，只差 bootstrap 注入 + Supervisor/CodeAuditAgent 消费点；补集成测试即可关闭 L1。
3. **POST /tasks 接 manifest 引用 + run 写 run_id**——小改动，直接对齐 §9 路由表。
4. **BudgetedLLM（L5）**——wrap `generate_with_usage`，按 run/Agent 计量 + 超预算结构化 `unavailable`。
5. **TargetProfile（L3）**——intake/profile.py + Supervisor 读取能力建议。
6. **run 目录校验脚本**——从一个 run_id 校验 trace/candidates/evidence/verification/metrics/checksums 完整性；统一 clusters.jsonl 产出。
7. （可选）L7 定向变体 / L8 反馈闭环——按路线图"实测证明增益后再加"，不作为当前必做。

> 保持不变的诚实红线：任何新阳性候选必须先过"可复现→根因→判重→人工复核"再定级；wasm3-surface 与 microtar 的现有定性（needs_more_evidence / known_duplicate）不得被后续文档改写。

## 7. 本轮关闭记录（2026-09-26 同日执行）

上表全部建议项已于同日实现并测试，逐项对照：

| 建议项 | 落地文件 | 验证 |
|---|---|---|
| L10 提示注入防护 | `llm/untrusted_input.py`（UntrustedExcerpt/redact/truncate/has_injection_hints/excerpt_prompt） | `tests/unit/test_untrusted_input.py` 全过（含敌对源码回归） |
| L1 接入主链 | `agents/code_audit_agent.py` 增 `ContextSlicer` Protocol + `bootstrap.py` 注入 `ContextSliceProvider()` | `tests/source_audit/test_code_audit_context_slices.py` 全过（含越界反例）；架构规则测试通过（不 import 具体实现） |
| §9 manifest 引用 + run_id | `api/routes/tasks.py`：`experiment_protocol` 校验（4 协议）、`target_manifest_id` opaque 校验、run 后写 `metadata.run_id` | `tests/unit/test_s6_readonly_api.py` 协议/run_id 用例 |
| L5 BudgetedLLM | `llm/budget.py`（RunBudget/BudgetLedger/BudgetedLLM/BudgetExhaustedError） | `tests/unit/test_budgeted_llm.py` 全过 |
| L3 TargetProfile | `intake/profile.py`（StudyTrack/TargetProfile/DefaultTargetProfiler）+ `bootstrap.read_profile_routes` 注入 Supervisor | `tests/unit/test_target_profile.py` 全过 |
| §9 run 目录校验 | `benchmark/archive_verifier.py`（必需产物/checksums 篡改/evidence 追溯/agent trace/run_id 一致性） | `tests/unit/test_archive_verifier.py` 全过（含篡改/缺失/不可追溯反例） |
| L7 定向变体 | `review/variant.py`（VariantHypothesis + Builder，track=guided_variant_search，无 CVE 标签） | `tests/unit/test_variant_hypothesis.py` 全过 |
| L8 反馈闭环（有限） | `fuzz/seed_proposal.py`（PlateauDetector + DeterministicSeedProposalProvider，只建议不执行） | `tests/unit/test_seed_proposal.py` 全过 |
| L9 WorkflowProfile | `intake/workflow.py`（4 个命名版本化配置） | `tests/unit/test_target_profile.py` WorkflowProfile 用例 |
| L4 ReproductionComparator | `benchmark/reproducer.py`（双版本同输入 N 次重放 + contrast_clean） | `tests/unit/test_reproducer.py` 全过 |

- 前端门禁：`npm run lint`（tsc --noEmit）、`npm run build`（vite）通过，dist 已更新。
- 全量回归：**862 passed / 2 skipped**（新增 52 用例）；`git diff --check` 无空白错误。
- 剩余如实保留项：SSE 为 §9 条件项（未要求）；L12 有向 fuzz 按文档决定暂缓；L11 网络/文件隔离如实标 `unsupported`；盲态自动命中真实漏洞仍为 0（TP=0），wasm3-surface 与 microtar 定性（needs_more_evidence / known_duplicate）保持不变。
