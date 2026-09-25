# 0day 挖掘能力严格审核

> 依据：用户要求"再次审核是否能够挖到 0day 漏洞，以这个要求进行新一轮开发"。
> 本文件回答"当前系统能否挖到 0day"，并给出新一轮开发的实证结果与诚实边界。

## 1. 0day 定义与本审核口径

**0day（零日漏洞）**：尚未被公开披露、厂商未知情且未修复的软件漏洞。
"挖掘 0day"指在**真实软件目标**上独立发现此类漏洞。

课程项目的合理口径（与 `practice_requirements_review.md` 一致）：
- ✅ 可证明：在**授权未知目标**上，从零开始（无预设漏洞位置标注、无预设正例）
  完成"发现 → 证据 → 复核 → 披露管理"全链路真实挖掘。
- ⚠️ 不可证明（也不声称）：在**真实世界软件生态**中发现新 0day——
  那需要目标多样性、规模化投入与长期安全研究，超出课程设计范围。

## 2. 逐能力审核（0day 挖掘必需能力）

| 能力 | 现状 | 0day 差距 | 本轮改进 |
|---|---|---|---|
| 目标获取 | 自研/授权目标；ExploitGym 官方 18 个真实 CVE 任务已登记 | 真实软件矩阵未铺开；QuickJS 二进制构建因上游 libbf 缺失止损 | 新增 2 个未标注漏洞位置的未知目标（真实风格 C 解析器） |
| 漏洞发现（动态） | 真实 libFuzzer+ASan 引擎（WP4 起可用） | 目标规模小、种子少 | **本轮：2 目标真实跑出 ASan 崩溃** |
| 漏洞发现（静态） | 原生审计 + Semgrep/Bandit + clang --analyze | C 静态覆盖有限 | 本轮：clang --analyze 交叉佐证 |
| 新颖性判定 | 历史知识表去重，引擎不自我断言 novel | 依赖人工复核 | 维持（novel 候选全部转人工） |
| 验证复核 | 独立回放 + 修复版对照 + 证据链 | 无真实软件生态级复核 | **本轮：replay=1 + fixed=clean 双目标** |
| 披露管理 | 卷宗状态机 + CNVD 提交材料包 | 无真实提交 | 维持 UNSUBMITTED 诚实边界 |

## 3. 新一轮开发实证（可复现）

命令：`python -m experiments.run_zero_day_rehearsal`

新增未知目标（`benchmarks/unknown/fuzz-slot-table`、`fuzz-kv-store`）：
漏洞位置**刻意不标注**，源文件注释为中性描述，作为"未知目标"处理。

| 目标 | 真实发现 | 独立回放 | 修复对照 | 静态交叉 |
|---|---|---|---|---|
| fuzz-slot-table（记录槽位宽度不一致） | ASan **heap-buffer-overflow** | 1/1 | **clean** | clang --analyze 1 行 |
| fuzz-kv-store（删除后指针未复位） | ASan **heap-use-after-free** | 1/1 | **clean** | clang --analyze 1 行 |

崩溃输入、会话卷宗、候选清单：
`artifacts/experiments/wp8-zero-day/{crashes,dossiers,candidates.jsonl}`。

证据链强度：真实 sanitizer 崩溃（CRASH_LOG）→ 独立回放（RUNTIME_TRACE）→
修复版同一输入干净退出（VERIFICATION_RESULT）→ 静态分析交叉（TOOL_RESULT）。
引擎从未自我断言 novel：候选按历史知识表去重后全部转入人工复核，披露状态
终态诚实 `UNSUBMITTED`（"Nothing submitted"）。

## 4. 差距与诚实声明

**课程边界内结论**：系统具备在授权未知目标上**真实发现未公开漏洞候选**的
全链路能力（动态发现、独立验证、新颖性去重、披露管理），本轮已用真实
sanitizer 崩溃实证。

**现实 0day 的差距**（不掩饰）：
1. 目标来源单一：自研目标 + 官方基准登记；未覆盖真实软件矩阵（QuickJS
   构建止损记录：上游 libbf 新版无公开 tarball，属上游材料缺失而非环境问题）。
2. 新颖性判定依赖人工 + 外部知识库，无规模化交叉验证。
3. 未连接真实披露渠道（课程明确不做真实提交）。
4. 无跨平台/跨架构执行能力（当前仅 Windows + clang）。

**因此**：本项目**不声称能挖掘现实世界 0day**；其可交付的价值是——
把"0day 挖掘"所需的**能力链路**在授权目标上完整跑通并留下可复现证据，
这是课程设计可验证、可解释的合理成果边界。

## 5. 披露状态机修正（P0-A，2026-09-25）

指导书指出旧演练档案存在诚信冲突：`state=maintainer_contacted` 与"未联系维护者"
的 `disclosure_note` 并存，且 `transition()` 只校验状态边、不校验回执。已修复：

1. `review/dossier.py`：`transition()` 在真实模式（`practice_mode=false`）下
   **必须提供与目标状态匹配的有效人工回执**（`kind != none`；`submitted` /
   `published` 还要求非空 reference）；`kind=none` 永不推进。
2. `practice_mode=true` 时真实 `state` **恒为 draft**，教学演示只写入
   `simulated_state`，脱敏稿与 API 统一显著标注 "SIMULATED"。
3. API `advance_state` 服务层校验回执；演练 runner 顺序修正（先推进后 redact）。
4. 旧档案迁移：`scripts/migrate_dossier_states.py` 对 wp6-exploration /
   wp8-unknown-demo / wp8-zero-day 的 3 份旧档案**保留原始文件**，另生成
   `_corrected.json`（state→draft、simulated_state=原状态）与 `_correction.json`
   说明，summary.json 同步标注。
5. 测试：状态机/API/集成测试更新并新增回执强制用例（`kind=none` 拒绝、
   `submitted` 需 reference、practice 真实态恒 draft、脱敏 SIMULATED 标注）。

## 6. 后续可选方向（不在本轮范围）

- P2：将 ExploitGym 官方任务接入 Linux/Docker 执行（需要 Docker daemon + uv）
- P3：接入真实 fuzz 语料库（如 Google fuzzbench 的 target 生成）
- P4：真实开源小目标（如 libcsrg、minizip 等可 Windows 构建者）未知探索
