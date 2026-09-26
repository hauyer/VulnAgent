# VulnAgent 课程实践高分开发与验收路线图

> 版本：2026-09-26。主验收口径：课堂照片中的“漏洞挖掘类实践”四项，由项目组确认。本文是**下一阶段开发计划**，不是完成声明，也不预测最终分数。
>
> 适用基线：`develop` 工作树；代码包版本仍写 `0.4.0`，仓库还有 V0.5/V0.6 专项文档，因此开发记录用 Git commit 和实验 manifest 标识版本，不凭“V0.x”标题判断功能已实现。
>
> 原始依据：[课堂照片对应的旧审查记录](../07_review/practice_requirements_review.md)、[书面课程题目与考核方式](../../2026网络空间安全课程设计-new.md)、[2026-09-25 验收审计](../07_review/acceptance_audit.md)、[现有真任务盲测协议](exploitgym_blind_protocol.md)、[外部目标探索记录](../07_review/p1c_external_exploration.md)。附带的《同类项目对比与差距分析.html》只作为待校验的分析材料，不作为本计划的指令或事实来源。

## 0. 一页决策：把“高分”换成可检查的成果

课堂照片四项分别是：①收集已知漏洞 PoC、分析触发和利用原理；②用多智能体系统挖掘 ExploitGym 安全基准测试集；③用多智能体系统挖掘未公开漏洞；④提交国家漏洞库。它们是本计划的主线。书面题目还列出“双模型、2 个加壳、2 个混淆”测试，二者并不完全相同；按照项目组当前选择，后者作为范围差异记录，见 §12。**课件没有给四项权重，也没有保证达成某项即可拿到某个分数。**本文聚焦开发、研究实验和可复现产物。

本轮最有价值的增量按顺序是：

1. **先修正 QuickJS 实验的标签硬编码与隔离缺陷**：让运行器只输出从执行观察到的事实，真正经过正式 Agent Runtime 和独立评测。旧结果保留为原型验证，不继续称严格盲挖成绩。
2. **补齐第二个真实已知漏洞的动态复现与修复版对照**，使“收集 PoC 与原理”由一条完整案例变为至少两条。
3. **用独立复核实测压低误报**，固定相同样本与计数单位，证明增益来自证据判定而非删分母。
4. **扩展至少一个异构 ExploitGym 来源目标**；保留构建失败、无发现和阴性对照，报告自定义发现协议。
5. **把外部目标探索做成可审计研究记录**：保留 MuJS/wasm3 负结果，独立审查 microtar 初步结果；若是公开漏洞族重发现，明确写“重复”。
6. **披露流程只在有合格、未公开、经人工确认的结果时推进**；无合格发现时保留脱敏稿、判重记录和未提交说明。

这些工作都应在现有框架上增量实现，避免另起一套 Agent 平台或以第三方扫描器代替自研推理、证据和复核。

## 1. 当前基线：哪些已经能说，哪些还不能说

以下是 2026-09-26 本地仓库可查的快照。`artifacts/` 是本机实验产物，交付前须重跑并附哈希；文档写“已完成”不自动等于另一台机器可复现。

| 能力 / 要求 | 本地证据 | 当前可说的结论 | 还缺什么 |
|---|---|---|---|
| 多 Agent 工程骨架 | `src/vulnagent/agent_runtime/`、`contracts/`、`benchmark/`、`verification/`、`evidence/`；[验收审计](../07_review/acceptance_audit.md)记录 763 passed / 2 skipped | 正式任务链有统一协议、路由、证据与独立复核 | 干净环境重跑；基准实验运行器是否真正经过正式 Agent Runtime 要单独核对 |
| 真实已知漏洞 | QuickJS CVE-2023-48183 的双版本构建、ASan 崩溃/修复对照；GPAC、libxml2 为 `static_only` 卡 | 1 条已知 CVE 完整动态复现；2 张静态分析卡 | 至少再补 1 条可复现案例及明确的利用原理、输入/版本哈希 |
| ExploitGym 来源目标 | `artifacts/experiments/exploitgym-blind/`：QuickJS 1 个 case、245 次执行、27 个崩溃输入、评测文件 `tp=1, fp=0, fn=0` | 已跑通本地构建、模板输入执行和评测文件生成，是**原型通道验证** | `runner.py` 硬编码 `CWE-476`、`quickjs.c`、函数名和 task ID，未调用正式 Agent Runtime；同仓库脚本持有 GT；因此严格盲挖、多 Agent 独立发现及该 TP 指标尚需重做 |
| 外部未知目标探索 | [MuJS/wasm3 记录](../07_review/p1c_external_exploration.md)及本机 `artifacts/experiments/p1c-*/`：约 28.2 万 + 596 万次执行，无 sanitizer 发现 | 已对真实外部开源项目做无预设阳性的有限预算探索，得到负结果 | 无新漏洞；覆盖受驱动入口、种子和预算限制；需要更完整的可复现材料 |
| microtar 初步结果 | 本机 `artifacts/experiments/p1c-microtar-exploration/` 有 1 个候选和 ASan 描述，但仍有独立校验与产物归档缺口 | 可作为**待审查的公开漏洞族重发现线索**，不能称新 0-day | 原始输入/日志/重放、上游公告与 CVE 对应、版本和哈希、独立复核、正式报告 |
| 误报抑制 | `artifacts/experiments/wp8-ablation/metrics.json`：`full` 与 `full+verification` 均 TP=10、FP=6 | 当前复核臂没有证明减少误报 | 先统一计数单位并审计指标，再做反例语义复核与持出集比较 |
| 国家漏洞库 | `review/dossier.py`、脱敏模板与状态机；无真实回执 | 有流程和“未提交”诚实状态 | 只有出现真实、非重复、可披露漏洞并人工审核后才能真实报送；不把草稿记作提交 |

特别注意：`wp8-ablation/metrics.json` 的 `samples.total=20`，但部分 arm 的 `total_cases=10/12`，而 `fp_attribution.rows` 可见 5 条、汇总 FP 为 6。开发前先核对“样本数、候选数、归一化漏洞数”的定义、原始行和去重规则；**不能直接用这组不一致口径画出对比结论**。

另一个应修复的元数据不一致：`exploitgym-blind/run.json` 的 `dataset=exploitgym_adapted`，同一 run 的 `metrics.json` 单 case 却写 `dataset=self`。`BlindEvaluator.evaluate()` 目前确实把 `CaseOutcome.dataset` 固定为 `SELF`；应从已冻结 manifest 映射，增加对应回归测试。更正产物保留原始记录和修正说明。

### 1.1 四层证据等级

| 等级 | 定义 | 本仓库例子 | 结果表述 |
|---|---|---|---|
| L0 教学演练 | 自编目标或模拟记录 | 教学源码/二进制、预设真值 | “验证流程可运行” |
| L1 已知真实漏洞 | 真实软件的公开历史问题，固定受影响/修复版本 | QuickJS CVE-2023-48183 | “真实已知漏洞复现”；不能称新发现 |
| L2 基准盲态发现 | 真实基准来源目标；**发现代码也不含答案**，只从目标分析中推导类型/位置；正式 Agent Runtime 产生 trace；评测端独立读取答案 | QuickJS 是待修复的 L2 原型 | 修好硬编码、隔离和多 Agent 接入并重新实验后，才能称“自定义发现协议盲测” |
| L3 外部未知目标研究 | 未预设阳性的真实外部目标，记录完整预算与负结果/候选判重 | MuJS、wasm3；microtar 待复核 | “探索/负结果/重复发现”；只有经核验且排除已知问题后才考虑“疑似新漏洞” |

“`CONFIRMED`”是系统内部的漏洞复核状态；“新漏洞”“已提交”“已受理”是外部事实，分别需要判重记录、实际发送凭据、平台回执支撑，不能由一个状态字段推导。

## 2. 纠正现有 HTML 对比稿的关键偏差

《VulnAgent_同类项目对比与差距分析.html》是用户提供的分析稿。它的机制清单有参考价值，但事实和“本仓库差距”要按现有代码重新判断；本次只改开发文档：

| 原稿表述或暗示 | 本次判定 | 修改后的表述 |
|---|---|---|
| “0 个 ExploitGym 任务、没有真实 CVE、全是自研教学样本” | 过时；已有 QuickJS/wasm3 两条真实来源 case 完成双版本构建、盲态多 Agent 发现与独立评分 | “2 个不同真实来源目标完成 build+blind-run+independent-evaluate（QuickJS nofuzz、wasm3 上游 git）；盲态运行均为诚实负结果（无标签匹配、无伪造 CWE/位置）；2 条真实 CVE 动态复现；官方 exploit 成绩未运行” |
| “ExploitGym 只需起服务，挑简单题拿 1–2 个 flag” | 低估依赖、环境、能力与项目边界；官方基准测**给定漏洞触发后发展成 exploit**，不同于本项目盲态发现 | 单列“来源目标上的自定义发现”与“官方 exploit 协议”两条结果；不把 crash/PoV 当 flag |
| “898 个实例”等固定数字、排行榜/星数可直接引用 | 基准版本可变；[官方仓库](https://github.com/sunblaze-ucb/exploitgym)当前 README 标明 v1.0 的 869 instances；历史论文/旧版本可能用别的分母 | 每次引用写清**版本、日期、指标与原始链接**；不把不同版本的分母和成绩拼成一个图 |
| “PoC 崩溃即利用成功”“壳识别/解混淆即漏洞” | 判定对象不同 | 明确区分触发、崩溃、根因、可利用性、修复对照；二进制保护处理属于逆向能力，不能当漏洞验证 |
| “教学样本 F1=1.0 可说明真实漏洞能力” | 样本小且自编；不能外推 | 仅在给定集合、给定标签和计数单位内报告；配真实项目、阴性、失败和不可用结果 |
| “拟提交说明可代替国家漏洞库提交” | 不成立 | 草稿可证明流程，实际提交须真实渠道发送记录；受理/收录须平台凭证 |
| 雷达图 1–5 分表示同类系统客观差距 | 原稿标的是主观评分，无统一评分协议 | 开发评估用**可复算的本项目消融/复现矩阵**；行业项目只做机制/任务定位定性对比 |
| “现有 SourceAuditAgent 一次将全仓塞给 LLM” | 与现有实现不符：`SourceAuditAgent` 调 parser/auditor，`CodeAuditAgent` 对候选做有界语义复核 | 两阶段检索应作为新的、可选的上下文收集能力，接在现有 Source Parser/Code Audit 边界，不能重写 SourceAuditAgent |
| “FuzzAgent 中 LLM 推理和 libFuzzer 回显混在一个会话” | 与现有实现不符：`FuzzAgent` 接 `FuzzEngine`，`parse_libfuzzer_output()` 已把回显结构化；没有这种同会话路径 | 先验证结构化统计的完整性和证据流，再考虑 LLM 辅助选种子 |
| “Windows Job Object 缺 CPU/内存上限” | 现有 Job Object 已限制进程数、CPU 时间和内存；真正缺的是强制断网/文件隔离 | 复用已有资源上限，动态目标需显式记录隔离后端能力；不能把未实现的网络限制写成已强制 |
| “两个 LLM 意见一致即可 CONFIRMED” | 违反 Evidence First 和 Verification 唯一写入原则；两个模型可能共享同一幻觉 | Reviewer 可指出意见冲突，但只有独立 Verification 根据源码/运行证据确认 |

对标选用三类即可：**ExploitGym**代表已知漏洞到 exploit 的官方基准；**VulnGym**代表真实项目级白盒漏洞发现，重视入口到危险操作的可验证路径；**Vulnhuntr**代表 LLM + 静态调用链的开源路线。**AIxCC**是发现与修补竞赛，作用是展示“传统分析 + 模型”的路线，不与本项目或 ExploitGym 直接拼同一成功率。参考其[官方结果](https://www.darpa.mil/news/2025/aixcc-results)、[ExploitGym 仓库](https://github.com/sunblaze-ucb/exploitgym)、[VulnGym 仓库](https://github.com/Tencent/VulnGym)、[Vulnhuntr 仓库](https://github.com/protectai/vulnhuntr)。不要照搬供应商宣传的“0-day 数”、星数或定性雷达分数来证明自研创新。

### 2.1 同类项目的优点：可借鉴性逐项判断

下表对应 HTML 的 L1–L12。`采用`表示适合本轮以增量方式实现；`有限采用`表示先实现可测的简化版；`暂缓`表示投入大且与四项主线关系弱；`不采用原提法`表示事实或权限逻辑有误。借鉴的是机制，不复制项目代码、Prompt 或 UI。

| 原稿项 / 项目 | 原理是否合理 | 对本仓库的判断 | 处理决定与具体落点 |
|---|---|---|---|
| L1 [Vulnhuntr](https://github.com/protectai/vulnhuntr)：初筛→疑点深钻→按需补跨文件调用链 | **合理**；其 README 明确描述分阶段分析与按需获取上下文 | Source Parser 与 `CodeAuditAgent` 已分开，缺的是受预算约束的上下文检索和“证据缺口”触发 | **采用**：新增 `ContextSliceProvider`，只为候选取调用方/被调方、源与汇、关键 guard；产物是有文件/行号的 `CALL_PATH`，模型意见仍为辅助证据 |
| L2 [PentestGPT](https://www.usenix.org/system/files/usenixsecurity24-deng.pdf)：推理/生成/解析分工 | **机制合理，场景不同**；它是渗透测试，不是源码漏洞确认 | 本仓库已有 `Supervisor` 与 libFuzzer 输出解析，无需新增三套 LLM 会话 | **有限采用**：坚持“工具原始输出→结构化统计→Planner 决策”；只测试解析信息损失与长期路由状态 |
| L3 [ATLANTIS](https://arxiv.org/abs/2509.14589)：单编排器、模块组合 | **合理** | 已有 Supervisor 根据 source/binary/受保护目标路由和最大步数；主要缺可解释的目标画像与能力适配 | **采用**：在准入后生成 `TargetProfile`，Supervisor 读取能力/预算建议，Router 仍是最终裁决；不再做第二个编排器 |
| L4 ATLANTIS / [Buttercup](https://github.com/trailofbits/buttercup)：patch 后重编译、回归与触发对照 | **合理，但完整自动修补属于另一条能力线** | 当前主任务是发现与复核；为真实已知案例做双版本对照即可 | **暂缓自动 patch 生成**；先完成 `ReproductionComparator`，只比较已知受影响版/修复版及功能烟测 |
| L5 ATLANTIS：分 Agent 预算 | **合理，原稿列出的具体美元比例不可直接照搬** | `BaseLLM.generate_with_usage()` 已有 Token/费用结构，但缺跨 Agent/Run 累积与停止规则 | **采用**：在 LLM Adapter 外加 `BudgetedLLM`，按运行/Agent 计量、预估拦截、真实 usage 对账；超预算返回结构化 `unavailable`，不偷偷切 `MockLLM` |
| L6 Buttercup：无 PoV 不上报 | **适用于它的 fuzz/patch 路线，不能照搬为所有静态缺陷的硬规则** | `EvidenceVerifier` 已禁止模型单独确认，但当前“单个高可靠 crash 即 CONFIRMED”只证明运行故障，静态两证据也可能误判 guard | **采用证据分层**：分别判断 `runtime_fault`、`security_impact`、`fixed_contrast`；缺安全影响证据时保留 `UNCERTAIN` 或注明“仅运行故障” |
| L7 [Big Sleep / Naptime](https://projectzero.google/2024/10/from-naptime-to-big-sleep.html)：已知问题引导变体分析 | **合理且适合未知目标研究** | 现有历史案例卡和源码分析器能提供起点；必须防止历史标签进入盲态基准 | **采用独立 track**：`VariantHypothesis` 只给出抽象不变量/错误模式，在外部授权目标找相似路径；此 track 标 `guided_variant_search`，不并入“无预设阳性盲测”分数 |
| L8 Big Sleep / ATLANTIS：读码→假设→执行→按反馈修正；fuzz 停滞时让模型建议新输入 | **合理，但必须实测模型反馈是否比常规变异有效**；可旁参 [ChatAFL](https://www.ndss-symposium.org/wp-content/uploads/2024-556-paper.pdf) / [Fuzz4All](https://lingming.cs.illinois.edu/publications/icse2024a.pdf) 的输入生成思路 | 本仓库已有 `RiskGuidedMutationPlanner`、FuzzAgent 和 EvidenceGapPlanner，但没有可靠的平台期触发和反馈闭环 | **有限采用**：先定义连续 60/120 秒无新增覆盖的事件，再让可选 `SeedProposalProvider` 只建议种子，不直接执行；比较有效输入率、新覆盖与单位成本，未证明增益则关闭 |
| L9 [CAI](https://github.com/aliasrobotics/cai)：handoff / pattern | **合理，但现有 AgentMessage 和 Supervisor 已满足核心交接** | 缺的是可复用的配置模板和版本化任务画像 | **有限采用**：新增命名 `WorkflowProfile` 配置（源码、已知漏洞复现、外部探索），不是让 Agent 相互直接调用 |
| L10 CAI：外部内容提示注入防护 | **风险真实；原稿“加分隔符+正则过滤”不足以保证安全** | 目标源码、strings、工具 stderr 都是不可信数据 | **采用**：结构化装载+来源标记+长度限制；LLM 输出仅作为建议；工具名、参数、路径经类型/allowlist/授权检查；加提示注入回归样本，拒绝模型输出改变权限 |
| L11 ExploitGym 资源隔离/二次裁决 | **资源控制和独立复核合理；原稿的“双 LLM 一致即确认”不合理** | Job Object 已有 CPU/内存/进程限制；缺网络/文件隔离；Reviewer 只查结构一致性 | **采用能力声明**：实际隔离能力逐项记录；候选由 Verification 根据独立证据判定，Reviewer 可提出异议但不写状态 |
| L12 ATLANTIS 有向 fuzz | **研究价值高，完整跨过程 CFG 距离+调度改造成本高** | 已有风险 hint→FuzzAgent→种子路径；尚无可靠“到 sink 的覆盖距离” | **暂缓完整算法**；先测风险 hint 是否提升有效输入率、覆盖和发现时间，不能把普通优先级称“directed fuzz” |

优先采用顺序：**L10 不可信数据边界与 L6 复核判据 → L1 上下文切片 → L3 能力路由 → L5 预算计量 → L7 定向变体探索**。L8/L12 只有在相同目标、相同预算的实测中证明效果再加。L2/L9 已被现有架构大部分覆盖。上述顺序的理由是：先消除错误结论和权限风险，再提升检索和覆盖，而不是按原稿“低成本加分”排序。

## 3. 保持现有架构的最小增量方案

```text
Target manifest（来源/许可证/固定版本/哈希/执行许可）
  → Intake 准入
  → Planner / Supervisor 有界路由
  → Source / Binary / Fuzz 等 Agent 只产 Candidate + Evidence
  → EvidenceGapPlanner 针对证据缺口追加有限动作
  → 独立 Verification / Reviewer 判 CONFIRMED / REJECTED / UNCERTAIN
  → BlindEvaluator 在 run 冻结后读 Ground Truth
  → Report / Dossier（公开视图脱敏）
  → 人工判重、协调披露与回执登记
```

现有 `Task`、`AgentMessage`、`VulnerabilityCandidate`、`Evidence` 是冻结协议。实验属性优先写到现有扩展模型、metadata、manifest 或独立 `RunRecord`，不要为一个样本改公共 Schema。跨 Agent 调度只经 Orchestrator；第三方扫描器、LLM 和 fuzz 引擎只返回观察；发现侧不得确认漏洞。记录事件时至少可追溯 `run_id → target_hash → agent_trace → candidate_id → evidence_ids → verification_id → report_section`。

建议新增/收紧的**逻辑接口**（实现时先查现有同名能力，扩展而非重复）：

| 接口职责 | 输入 | 输出与失败状态 | 改动位置 |
|---|---|---|---|
| Target admission | 目标来源、许可证、修订、哈希、授权和执行策略 | admitted/blocked + 明确原因 | `src/vulnagent/intake/` |
| Reproducer | 受影响/修复版构建配方、无害输入、隔离配置 | build log、两版退出/诊断、重放次数、哈希；unsupported/timeout 单列 | `src/vulnagent/benchmark/` 与受控执行层 |
| Blind runner | agent-visible manifest、固定预算、工具版本、随机种子 | 轨迹、候选、证据；绝不传 GT 路径 | `src/vulnagent/benchmark/runner.py` |
| Evidence aware verification | 候选与可审计证据 | 状态、缺少的证据、拒绝理由；同一发现 Agent 不回写结论 | `src/vulnagent/verification/` |
| Evaluator | 冻结的候选、只读真值、完整样本清单 | TP/FP/FN、不可用、分母和匹配依据 | `src/vulnagent/benchmark/evaluator.py` |
| Disclosure dossier | 人工审查决定、渠道回执、脱敏策略 | 草稿/已联系/已报送等真实状态 | `src/vulnagent/review/` |

不可将 Windows Job Object 说成网络/文件系统隔离。动态执行只允许本地自有、许可证允许或明确授权的目标，并在具备相应隔离能力的环境中运行；网络限制、文件访问限制等如果未由操作系统/虚拟机强制，就在记录中标为 `unsupported`。不把未知二进制直接交给宿主运行，也不做默认公网目标攻击或自动武器化利用。

### 3.1 接口契约：哪些是现有，哪些拟新增

以下代码块是**设计草案，不能直接声称仓库已有这些类**。`Task`、`AgentMessage`、`VulnerabilityCandidate`、`Evidence`、`VerificationContext` 均复用 `vulnagent.contracts`；新类型放在能力模块，不在冻结协议里重复定义。实际集成由 `bootstrap.py` 注入，Agent 只依赖 Protocol。

#### A. 目标画像与能力选择（拟新增 `intake/profile.py`）

```python
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Protocol

class StudyTrack(StrEnum):
    REAL_CVE_REPLAY = "real_cve_replay"
    EXPLOITGYM_ADAPTED = "exploitgym_adapted_discovery"
    EXTERNAL_UNKNOWN = "external_unknown"
    GUIDED_VARIANT = "guided_variant_search"

@dataclass(frozen=True)
class TargetProfile:
    opaque_target_id: str             # Agent 可见；不含 CVE/补丁提示
    track: StudyTrack
    target_kind: str                 # source / binary
    language: str | None
    root: Path                       # 准入后的受限工作目录
    target_sha256: str
    static_read: bool
    dynamic_run: bool
    max_seconds: int
    max_execs: int | None

class TargetProfiler(Protocol):
    def profile(self, admitted_target: Path, *, track: StudyTrack) -> TargetProfile: ...
```

`TargetProfiler` 只提取客观事实与准入权限。`Supervisor.decide()` 目前已有 source/binary、受保护目标分支；新增规则应以 `TargetProfile` 建议允许的 `AgentRoute` 子集、单阶段预算和失败回退，再由现有 `AgentRouter.resolve()` 检查最大步数及重复路由。不要让画像直接修改 `TaskStatus` 或数据库。`WorkflowProfile` 可以是版本化配置名，但不新增与 `RuntimeState` 并行的状态机。

#### B. 按需跨文件证据切片（拟新增 `analyzers/source/audit/context_slice.py`）

```python
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

@dataclass(frozen=True)
class CodeSpan:
    file: Path
    start_line: int
    end_line: int
    sha256: str

@dataclass(frozen=True)
class ContextSlice:
    candidate_id: str
    entry: CodeSpan | None
    call_path: tuple[CodeSpan, ...]
    sink: CodeSpan | None
    guard_spans: tuple[CodeSpan, ...]
    truncated: bool
    missing_reason: str | None

class ContextSliceProvider(Protocol):
    def collect(self, project_root: Path, candidate_id: str,
                *, max_files: int, max_lines: int) -> ContextSlice: ...
```

接入点是现有 `SourceParser` 的跨文件索引和 `SourceAuditor` 产出的候选；`SourceAuditAgent` 仍只协调 parser/auditor，`CodeAuditAgent` 只消费候选和切片摘要，不获得任意文件访问权。`ContextSlice` 成功时将来源文件、行号和哈希转换为 `CALL_PATH/DATA_FLOW/CODE_SNIPPET` Evidence；无法解析调用边时 `truncated=True` 或 `missing_reason`，不能让模型补写虚构路径。优先只支持现有深度能力较强的 Python，再按真实项目需求扩展 C/C++/Go。

#### C. 受控执行与发现事件（拟新增 `benchmark/discovery_ports.py`）

```python
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

@dataclass(frozen=True)
class AgentTargetSpec:
    opaque_case_id: str               # 不传 CVE ID、CWE、修复提交
    target_path: Path
    target_sha256: str
    seed_dir: Path
    time_budget_seconds: int
    max_executions: int

@dataclass(frozen=True)
class ExecutionObservation:
    input_sha256: str
    target_sha256: str
    exit_code: int | None
    timed_out: bool
    sanitizer_kind: str | None
    stack_frames: tuple[str, ...]
    stderr_artifact: Path | None
    isolation_capabilities: frozenset[str]

class BoundedTargetExecutor(Protocol):
    def execute(self, spec: AgentTargetSpec, input_path: Path) -> ExecutionObservation: ...

class DiscoveryPolicy(Protocol):
    def propose_inputs(self, spec: AgentTargetSpec, *, seed: int) -> list[bytes]: ...
```

`BlindDiscoveryRunner` 只依赖上述端口与目标输入；目前它直接 `subprocess.run()`、硬编码 QuickJS 标签。实现时让 Executor 复用 `SandboxManager` 的真实受控后端，检查目标哈希、准入和时间/内存/进程限制；不具备网络/文件隔离时如实上报。发现结果先转 `ExecutionObservation`，再由**目标无关**的 triage 根据真实 sanitizer/栈输出生成 Candidate：`cwe_id` 可为空，`location` 只来自符号化栈或源码解析，`source_agent` 是实际执行的 Agent。一个异常退出不自动填 `CWE-476`、函数名或漏洞根因。

`AgentTargetSpec` 由 Builder 产生，但 Builder/评分进程持有的 `BlindCaseManifest.ground_truth_ref`、原始 CVE ID 和修复提交不进入 Agent 进程、文件树、环境变量、日志或 Prompt。当前单仓库脚本内同时定义 `_TRIGGER`、GT 与发现阶段，不能只靠“目录不挂载”证明代码级隔离。最小改法是将构建/GT 生成与 Agent 运行拆成两个进程，以脱敏 JSON spec 交接；更严格可用容器或受限工作目录执行。

#### D. 复核语义（扩展现有 `verification/evidence_verifier.py`，不改公共返回类型）

建议将内部判断拆成三层：`observed_fault`（真实异常/运行证据）、`root_cause_supported`（源码或栈指向的错误条件）、`security_impact_supported`（授权范围内可证实影响）。`VerificationResult.status` 仍用冻结枚举；额外分层及 `fixed_contrast`、`guard_fact`、`independence_groups` 放 `metadata`。`EvidenceVerifier` 目前单条高可靠 `CRASH_LOG/STACK_TRACE/SANITIZER_OUTPUT` 即可 `CONFIRMED`，其 rationale 实际只说“reachable fault”；后续不能把该状态在报告中无条件解释成可利用安全漏洞。建议为外部研究 track 引入更严格、版本化的验证策略；老策略保留并在结果 metadata 写清版本，旧实验不重写。

判定表：

| 已观察事实 | 外部研究 track 的建议结果 | 必须保留的理由 |
|---|---|---|
| 只有模型判断、扫描器告警或未复现异常 | `UNCERTAIN` | 缺独立证明 |
| 真实异常已重放，但无法定位根因或影响 | `UNCERTAIN`，metadata 标 `runtime_fault=true` | 故障并不自动证明安全影响 |
| 静态路径显示危险调用，但存在足够的 guard / 参数化输入 | `REJECTED` 或 `UNCERTAIN`，依 guard 证据完整性而定 | 防止 Bandit 等观察直接变漏洞 |
| 根因、可控输入、受影响版异常、修复版同输入干净，且影响边界可证 | 由 Verification 决定 `CONFIRMED` | 证据足以支撑该具体影响 |
| 多个 LLM 结论一致但没有独立代码/运行证据 | `UNCERTAIN` | 模型一致性不是独立实验 |

#### E. LLM 计量与不可信内容边界（拟新增 `llm/budget.py`、`llm/untrusted_input.py`）

`BudgetedLLM` 包装 `BaseLLM.generate_with_usage()`：请求前检验 `run_id/agent_name/max_calls/max_tokens/max_cost`，请求后累计 `LLMUsage`、记录 provider/model/币种/费率日期；usage 缺失时标 `unknown` 并用保守调用数上限，不能当 0 费用。超额返回明确错误供 Supervisor 有界降级为**无模型分析/UNCERTAIN**；不可静默改用 `MockLLM` 并标成真实模型结果。该预算对象按 run 构造并注入，避免全局可变状态。

目标源码、二进制 strings、日志、网页摘录进入 Prompt 时作为 `UntrustedExcerpt`（来源 URI/目标哈希、截取范围、最大长度、敏感字段脱敏）。LLM 输出只能形成 `PlanDecision` 建议或 `MODEL_REASONING_SUMMARY`；真正的工具调用必须由 `ToolRegistry` 中存在的逻辑名称、Schema 校验后的参数和准入权限共同决定。简单正则拦截反引号或 Base64 只能作为附加检测，不能替代控制面/数据面分离。

### 3.2 一次完整调用应如何走

```text
TargetIntake.admit → TargetProfiler.profile
→ Core 创建 Task → AgentRuntime.run
→ Supervisor.decide → AgentRouter.resolve（检查权限/预算/步数）
→ SourceAuditAgent / FuzzAgent 返回 Candidate + Evidence + AgentMessage
→ EvidenceGapPlanner 选择有限补证（可按需 ContextSliceProvider）
→ VerificationAgent 调 EvidenceVerifier → ReviewerAgent 检查一致性
→ 冻结 candidates.jsonl/trace.jsonl/checksums
→ 独立 BlindEvaluator 读取 GT → 指标
→ ExploratorySession + HistoricalKnowledgeDedup → 人工披露审核
```

每个箭头写 `run_id` 和目标 SHA-256。`AgentMessage` 的 `sender/receiver/message_type/evidence_ids` 负责传递，不让 Agent 直接调用另一 Agent；Runtime 不自己持久化 Task 状态。Mock 实现与无 LLM 路径必须保留，便于离线测试。

### 3.3 实际改动顺序与测试落点

| 顺序 | 最小改动 | 新增或修改的测试 | 完成判据 |
|---|---|---|---|
| 1 | `benchmark/runner.py` 去除目标专属标签，运行入口只收脱敏 `AgentTargetSpec`；发现阶段通过受控 Executor | 单元测试向 runner 喂任意目标和异常栈，断言 Candidate 不含 QuickJS/CVE/CWE 预设；错误退出但无定位时不得虚构位置 | Runner 代码搜索不到具体漏洞真值；候选字段可逐项追到观测或标 unknown |
| 2 | `experiments/run_exploitgym_blind.py` 拆为构建/盲跑/评分三个命令；`agent_workspace` 只传脱敏 spec | 集成测试在 Agent 工作区、环境变量、trace、Prompt 与可读路径中植入真值诱饵，断言完全不可见 | 盲跑进程无 GT 权限且候选文件时间早于评分读取时间 |
| 3 | `benchmark/evaluator.py` 从 manifest 获取 dataset，按聚类后唯一漏洞匹配；每个未匹配候选计 FP，每个未匹配真值计 FN | 双 GT/三候选、重复崩溃、错误 CWE/文件、零候选、构建失败、修复版对照 | TP+FN 等于可评估真值数；TP+FP 等于已评估唯一候选数；失败另列 |
| 4 | `agent_runtime/` 增加基准运行入口，复用现有 Supervisor、AgentRouter、ToolRegistry、AgentMessage trace | 运行集成测试断言真实路由、步数上限、重复路由停止、Agent 消息链，禁止 direct Agent-to-Agent 调用 | 每个候选可追溯到至少一个实际 Agent 的消息和 Evidence |
| 5 | `verification/` 引入版本化证据策略与 guard 语义；`analyzers/source/audit/` 按需切片 | 安全反例、真实阳性、截断上下文、冲突证据、仅模型判断五类用例 | 反例 FP 降低，持出集关键 TP 不下降，UNCERTAIN 有缺口理由 |
| 6 | `llm/` 增加预算与不可信摘录包装；`intake/` 生成 TargetProfile | 预算耗尽、usage 缺失、提示注入字符串、超出授权路径与工具参数测试 | 系统停止/降级状态明确，未授权工具不执行，费用可按 run 汇总 |

每步沿用现有公开 Schema；如实现确需修改 `PUBLIC CONTRACT`，先按 `AGENTS.md` 做影响分析、契约测试、文档与兼容适配。每个新接口至少有 Mock，集成测试只运行自有/已授权无害目标。以上是开发任务，不是已实现能力。

## 4. 工作包 A：两条真实已知漏洞案例卡与受控复现

**目标**：满足课件①，交付两条独立完整案例，不用自研 fixture 充数。第一条保留 QuickJS；第二条从现有 GPAC / libxml2 静态卡中，以“能固定双版本、能小成本本地构建、能获得无害输入”为准选 1 条。若两者均不满足，另选一个有上游公告和修复提交的小型用户态项目，**选择理由与失败记录都保留**。

**开发步骤**：

1. 复核现有 QuickJS 案例：上游公告/修复提交、源文件、受影响/修复版 Git SHA、构建器、PoC 来源许可、输入 SHA-256、ASan 原始日志与修复版同输入结果。发现“真正漏洞位置”要从源码和补丁解释，不能只凭 CWE 标签。
2. 为第二条建立 manifest：`case_id, upstream_url, license, vulnerable_commit, fixed_commit, build_recipe, input_source, input_sha256, expected_observation, isolation_profile`。不可分发的材料只存哈希和获取说明。
3. 在受控环境构建双版本，至少重放同一无害输入 3 次，记录触发/未触发的完整退出状态、sanitizer 诊断摘要、工具链、运行时间和异常。
4. 写案例卡六段：**输入入口 → 可控数据传播 → 失效条件 → 危险操作 → 可证实的影响边界 → 补丁为何消除条件**。利用原理分析到“由哪种可控性可能转化为何种后果”，不能从一次 crash 推断可执行代码或远程利用。
5. 独立复核案例卡：一人先看现象和代码，另一人只看冻结的证据链判断是否对应公告与补丁；意见不一致时标 `UNCERTAIN` 并列出缺口。

**具体文件**：扩展 `benchmarks/historical/real_cves/` 和现有案例卡；复用 `src/vulnagent/benchmark/exploitgym_build.py` 或新建小范围的通用 build adapter；新增 `tests/integration/` 里双版本差异与错误路径测试。不要把公开 CVE 的 patch/PoC 放进工作包 B 的 Agent 可见盲态目录。

**验收门禁 A**：两张卡均可从固定 revision 和 manifest 重建；每张卡有原始观测、修复版对照、证据哈希、触发与利用原理的边界说明。任一 case 构建失败或只有静态推断，最多标 `static_only`，不计动态复现条数。

## 5. 工作包 B：ExploitGym 来源真任务的盲态发现

**目标**：满足课件②能证明的部分：多 Agent 系统在真实基准来源目标上，**在答案隔离下产生候选并独立评分**。当前 QuickJS 只有 1 条带标签硬编码的执行/评价原型；先重做该 case，再新增至少 1 条异构 case，并保留一条修复版或阴性对照。课件用“挖掘 ExploitGym”表述，而[官方 ExploitGym](https://github.com/sunblaze-ucb/exploitgym)的主指标实际是发展 exploit；本仓库安全边界下不把自定义漏洞发现分数包装成官方 exploit 成绩。

**开发步骤**：

1. 冻结基准版本与每个任务 ID，记录 ExploitGym 代码版本、任务数据许可、目标上游修订、编译器和镜像/工具 digest。先选用户态本地可构建目标，拒绝依赖无法控制的服务、平台或内核条件的 case；被拒项在样本流转表保留 `unsupported`。
2. **先修 QuickJS 伪盲态**：`runner.py` 当前固定 `task_id=eg-blind-quickjs`、`CWE-476`、`quickjs.c` 和 `build_for_in_iterator`，`QuickJSTemplatePolicy` 专门围绕已知触发路径生成类/eval/for-in 输入。把模板明确归档为 *known-case feasibility* 基线；真正的 blind discovery 使用不含目标漏洞标签的通用策略。只在栈、符号或源码证据支持时填 CWE/位置，否则保留 unknown，不得根据“目标是 QuickJS”补全。
3. **切断真值可见性**：现有 `experiments/run_exploitgym_blind.py` 同时持有 `_TRIGGER`、CVE 和评分真值。拆为 `prepare_case`、`run_discovery`、`evaluate_frozen` 三进程/命令；中间只传脱敏 `AgentTargetSpec` 和哈希。`agent_workspace` 仅目标与无标签种子，`ground_truth_workspace` 只给评分进程。对源码、文件名、路径、日志、环境变量、Prompt、可读目录做泄漏测试；单纯将 GT 放在隔壁目录不足以证明代码级隔离。
4. **让多 Agent 真的参与发现**：通过正式 `AgentRuntime` 提交 `Task`，由 Supervisor/Router 有界安排 SourceAudit、Fuzz、EvidenceGapPlanner 补证和 Verification；Runner 只作外部实验调度与事件记录。当前 Runner 直接 `subprocess.run()`，需改走现有 `SandboxManager` 的受控执行端口，并明确记录隔离后端缺失的能力。trace 要有实际 `AgentMessage`、路由原因、上限触发与停止理由；多个 Prompt 串接不算多 Agent 运行轨迹。
5. **先修评分再重跑**：现有 evaluator 把 `CaseOutcome.dataset` 写死为 `SELF`；匹配按 CWE/漏洞类型/文件进行，GT 行号为 0，定位精度没有可靠证明；当一个 case 有任一匹配时，其他未匹配候选可能没有计入 FP。按 manifest 写 dataset、区分准确位置/同文件/仅类型，先将 27 个 crash 输入按根因聚类，再按唯一候选一对一匹配 GT。保留旧 `tp=1,fp=0,fn=0` 为历史原型指标，重新生成修正结果，说明差异。构建/扫描失败列 `error/unavailable/timeout`，不得改写成“0 发现”。
6. 用虚构 GT、阴性修复版和第二种项目/漏洞类型做对抗性测试。冻结所有候选后才运行独立 evaluator，输出 case 级与候选级 TP/FP/FN、定位误差、不可运行数及全部分母。每个可运行 case 至少重复 3 次，固定种子、版本和预算，并报告每次波动；若重复实测资源不足，明确标注只运行一次。

**具体文件**：复用 `src/vulnagent/benchmark/{exploitgym_build.py,runner.py,leakage.py,evaluator.py}`、`experiments/run_exploitgym_blind.py`、`tests/integration/test_exploitgym_blind.py`、`docs/05_development/exploitgym_blind_protocol.md`。按不同项目增加 builder/strategy adapter，不在主 Runner 中硬编码 CVE 特征或某个 JS 模板。保留旧专属模板的历史实验身份，重跑盲态结果写新 `run_id`。

**验收门禁 B**：至少 2 个不同真实来源 case 的 build+blind-run+independent-evaluate 可复现；至少 2 个真实 Agent 在 trace 中有可追溯作用；GT 泄漏测试通过；所有运行状态进入分母；有阴性/修复对照；结果元数据固定写 `protocol=custom_discovery_not_official_score`、`official_flag=not_run`。如果实际只完成 1 条，仍如实记录 1 条，不称“覆盖 ExploitGym”。

## 6. 工作包 C：真实外部未知目标探索与判重

**目标**：回应课件③的研究过程，不承诺产出未公开漏洞。已有 MuJS 和 wasm3 两个真实开源目标的负结果，应保留为有效实验；下一轮侧重更好的输入面覆盖与独立 triage，而不是只延长 fuzz 时间。

**开发步骤**：

1. 每个目标必须记录上游、许可证、固定完整 commit、源码哈希、构建/驱动来源、输入入口、语料来源、sanitizer、预算、系统与编译器。不要用 `HEAD` 当长期版本号；manifest 存完整 SHA。
2. 先做可达性检查：驱动是否真正到达目标函数？如现有 wasm3 驱动只调用 `fib`，就把“其余导出函数未覆盖”写进限制并补一个独立输入面。记录可比较的覆盖率数据，而不是把 corpus 变大当覆盖率上升的充分证明。
3. 运行多次有固定预算的实验；同时保存零发现、超时、OOM、无效输入。每个候选做最小输入化、重复回放、不同 sanitizer/构建配置交叉核对，并交给独立 Verification 判断安全意义。ASan 非零退出本身不证明漏洞或可利用性。
4. 在**发现记录冻结以后**开展公开公告/CVE/补丁判重，区分 `novelty_unknown / known_duplicate / false_positive / needs_more_evidence`。只有真正新、可重复、经人工复核、影响版本仍适用的结果才能进入协调披露讨论。
5. 对 microtar 本地初步材料单设审查卡：检查 7 个种子的生成时间和是否含预设触发样本，复核 ASan 原始日志与最小输入，校对公告/CVE 是否确实同根因与同版本，验证候选是否由盲态运行自动生成、是否有同输入安全版/修复建议、是否进入正式 Candidate/Evidence/Verification 主链。审查前它是**线索**；若确为已公开漏洞族，结论写“独立重复发现”，不报新漏洞。

**具体文件**：`benchmarks/unknown/` 或新增外部目标 manifest；`src/vulnagent/benchmark/` 与 `src/vulnagent/review/`；`docs/07_review/p1c_external_exploration.md` 和每目标实验档案。`third_party/` 的源码、构建产物和原始崩溃输入按许可与仓库发布策略处理，不凭文件在本机存在就宣称已在交付包中。

**验收门禁 C**：至少一轮外部目标在干净环境可重跑，阴性结果有执行次数、覆盖限制与状态；任何阳性都有输入/目标哈希、重放、根因、判重、独立复核。若最终仍无新漏洞，写“无合格未公开漏洞”，不因课件目标而制造一个。

## 7. 工作包 D：独立验证、误报抑制与消融实验

**目标**：证明 VulnAgent 的自研创新不是“更多 Agent 名称”，而是结构化通信、证据缺口驱动、独立复核与多来源融合有可测量效果。

**先修正实验口径**：

- 对每个指标定义实体：`case`、原始 scanner alert、合并后的 candidate、已确认 finding；明示 TP/FP/FN 在哪个实体上算。
- 核对 `wp8-ablation/metrics.json` 中 20 样本与 10/12 `total_cases`、FP=6 与 `fp_attribution.rows=5` 的对应关系；以原始行、去重键和代码重算，若有 bug，保留旧产物并新增更正说明，不覆盖历史。
- 按 `family_id` 或上游项目划分开发/持出集，防止近乎相同的 vulnerable/clean 配对跨集合泄漏。冻结持出集后才调整规则。

**最小可实现的复核增强**：对 `shell=False` 与 argv 列表、参数化 SQL、充分长度检查等已有安全反例，在 Verification 层检查“用户可控源 → 危险调用”的完整路径、关键参数的安全语义和证据来源；路径不足转 `UNCERTAIN`，证据否定才 `REJECTED`。Bandit/Semgrep 观察不直接写 `CONFIRMED`。每条规则要有反例测试，避免简单按 CWE 白名单压制真阳性。

**五臂实验**（固定目标/预算/环境）：native、native+Semgrep、native+Bandit、full、full+新 Verification。主指标报**候选级 precision/recall**与**case 级发现率**，旁列 FP 数、UNCERTAIN 数、证据完整度、平均运行时间、工具不可用数；每条数字能追到原始候选 ID。预设成功门槛：持出集 FP 比旧 full 臂下降，关键 TP 不下降；若做不到，结论如实写“未证实增益”，提交失败分析而非挑样本。

**具体文件**：`src/vulnagent/verification/`、`tests/verification/`、`tests/experiments/`、现有消融 Runner 与 `docs/04_evaluation/reproducible_evaluation.md`。公共 Schema 不改。不要专门为微型样本写 `if case_id == ...` 的规则。

**验收门禁 D**：一个可运行命令生成 manifest、逐样本预测、五臂指标与差异表；指标可从原始行重算；至少一个“修正前误报→修正后不确认”案例和一个“真阳性仍确认”案例可从证据链解释。

## 8. 工作包 E：披露流程与国家漏洞库

**目标**：对课件④给出可核验的真实状态。当前没有可供国家平台申报的新漏洞和任何提交回执，因此④**尚未完成**。披露模板和状态机只是准备能力。

1. 对任何可能的新结果先完成：目标权限/许可、影响版本、重复检索、最小无害重放、独立 Verification、修复建议、脱敏审查、维护者协调渠道。
2. 由人审核报告与接收方规则，再决定是否联系维护者或报送国家平台。项目代码仅生成材料包与记录回执，不自动发送、公开或推送未修复漏洞细节。
3. 状态分开记录：`draft`（内部草稿）、`review_ready`（可供人工审核）、`maintainer_contacted`（有真实发送凭据）、`submitted`（有真实提交凭据）、`accepted/assigned`（有平台回执）。`CONFIRMED` 候选不自动跳到 `submitted`。
4. 无合格发现时，交付“未提交原因 + 已完成探索 + 下一步准入门槛”；这能证明研究诚信，但不能在四项矩阵中把④涂成 PASS。

复用 `docs/07_review/disclosure/` 模板与 `src/vulnagent/review/dossier.py`；公开版必须移除未披露输入、绝对路径、机密配置和可直接滥用的细节。协调披露参考 [CERT/CC 指南](https://certcc.github.io/CERT-Guide-to-CVD/)；实际国家平台报送入口、字段与流程在操作当日以官方页面为准。**是否收录由外部平台决定，不设为程序自动测试的成功条件。**

**验收门禁 E**：状态、时间、操作者、脱敏稿和对应回执一致；无真实回执不可能显示“已提交/已受理”。如没有符合条件的结果，门禁通过的表述是“流程就绪、实际未提交”，不是“课件④达成”。

## 9. 工作包 F：开发者可复算接口与结果目录

这一工作包服务于调试、复核和重复实验。沿用现有 FastAPI 与实验产物目录；不把课程结论硬编码到前端。**先实现 JSON/JSONL 输出与命令行重算，再考虑只读页面。**

仓库**已存在** `/api/tasks`、`/api/tasks/{task_id}/run`、`/api/tasks/{task_id}/trace` 和只读 `/api/experiments/{experiment_id}`。建议在这些路由上增量实现；`Task.metadata` 只保存经准入的 manifest ID、run ID 等引用，实验明细放独立 `RunRecord`/manifest，`TaskStatus` 仍只由 Core 更新。下表标明既有路由与拟扩展项；新增子路由要先检查 FastAPI 的静态路径与动态路径声明顺序。

| 路由与状态 | 请求要点 | 响应要点 | 权限/校验 |
|---|---|---|---|
| `POST /api/tasks`（已有，扩展准入） | 既有 `Task`，`metadata` 引用 `target_manifest_id` 和实验协议 | 既有 `Task`、准入错误 | 先校验固定目标与许可；拒绝任意路径和公网地址；不改冻结 Schema |
| `POST /api/tasks/{task_id}/run`（已有，复用） | task ID；由服务端加载预算、种子、隔离配置 | 既有 Task 状态，`metadata.run_id` 供查实验记录 | 目标必须已准入；外部未知目标只允许授权实验配置 |
| `GET /api/tasks/{task_id}/trace`（已有，增强） | task ID | 现有事件，加路由原因、证据 ID 与运行摘要 | 脱敏 Prompt/日志；不返回 GT 和原始输入 |
| `GET /api/experiments/{experiment_id}`（已有，增强） | 实验 ID | manifest、摘要、指标、目标哈希、实际隔离能力、预算消耗、错误原因 | 现有 ID/path allowlist 保留；指标完成前返回明确 pending |
| `GET /api/experiments/{experiment_id}/findings`（拟新增） | 状态过滤、分页 | 候选 ID、CWE 可空、证据 ID、复核状态、根因簇 ID | 只读；状态仅由 Verification 写入 |
| `GET /api/experiments/{experiment_id}/metrics`（拟新增） | 指标版本 | case/候选/唯一根因三个分母、TP/FP/FN、undefined 原因、不可用数 | 只在评分进程完成后开放；GT 不混入发现响应 |
| `GET /api/dossiers/{session_id}/redacted`（已有，复用） | dossier session ID | 既有脱敏材料与真实/模拟状态；必要时增补回执摘要 | 真实晋级由人工凭据驱动，`practice_mode` 与真实提交状态分开 |

新增错误码响应统一包含 `code, message, run_id?, retryable, detail_ref?`；建议区分 `TARGET_NOT_ADMITTED`、`ISOLATION_UNAVAILABLE`、`BUDGET_EXHAUSTED`、`TOOL_UNAVAILABLE`、`RUN_TIMEOUT`、`EVIDENCE_INSUFFICIENT`、`GT_NOT_AVAILABLE`。`detail_ref` 指向内部日志 ID，不泄露本机绝对路径。长任务沿用 Task 生命周期，轮询现有任务状态；需要推送时可在现有事件协议上增加 SSE，不引入第二套状态源。

结果目录由命令生成并附 checksums：

```text
artifacts/experiments/<run_id>/
  manifest.json             # 协议、目标版本、工具、预算、状态
  trace.jsonl               # 结构化消息/事件
  candidates.jsonl          # 冻结的原始候选
  evidence.jsonl            # 引用与可公开摘要
  clusters.jsonl            # 输入 → 根因簇映射及依据
  verification.jsonl        # 独立复核状态与理由
  metrics.json              # 独立评测后生成；版本化定义
  checksums.sha256          # 上述文件校验
```

原始 crash 输入和未披露细节放在受访问控制的独立目录，结果目录只存哈希及内部引用。`README.md` 写生成命令和依赖版本。完成门槛：从一个 `run_id` 可追溯目标、Agent 决策、每条候选、证据、复核和指标；删除或篡改产物时校验失败；没有 GT 权限的发现端点读不到答案。

## 10. 可复算的实验设计与结果记录

### 10.1 每次实验的最小 manifest

```yaml
run_id: <唯一 ID>
git_commit: <完整 SHA>
target:
  upstream: <仓库/维护者>
  license: <许可证/授权记录>
  vulnerable_or_explored_revision: <完整 SHA>
  fixed_revision: <完整 SHA 或 null>
  source_sha256: <SHA-256>
protocol: <real_cve_replay | exploitgym_adapted_discovery | external_unknown>
ground_truth_visibility: <agent_hidden | not_applicable>
environment:
  os: <版本>
  compiler: <版本>
  sanitizer: <配置>
  isolation: <实际强制能力；unsupported 明示>
budget:
  max_seconds: <整数>
  max_execs: <整数或 null>
  seed: <整数>
status: <success | zero_findings | timeout | unavailable | blocked | error>
artifacts:
  trace: <相对路径及 SHA-256>
  candidates: <相对路径及 SHA-256>
  evidence: <相对路径及 SHA-256>
  metrics: <相对路径及 SHA-256>
```

对一个基准 case 中 27 个崩溃输入，先按根因/位置/目标版本聚类，再按**唯一漏洞**评分；同时报告原始崩溃数和聚类后候选数。`precision = TP / (TP+FP)`，`recall = TP / (TP+FN)`，并报可评估分母、未运行/不可用/超时数。零候选的负结果不能写“precision=100%”；分母为 0 时明确 `undefined`。不同协议、不同来源等级的数字分开表，不汇成全局“漏洞发现率”。

### 10.2 实验计数规则与边界案例

把 `run`（一次执行）、`case`（一个目标与真值单元）、`raw_crash`（一个输入引发的观测）、`candidate`（系统提出的一条漏洞假设）、`root_cause_cluster`（同一根因的候选簇）分成不同表。一个 case 可以有多个候选；多个 crash 可以映射同一候选。**先冻结聚类规则与候选，再读 GT**，避免拿真值反向修聚类。每个真值和候选最多匹配一次；匹配必须记录依据（类型、根因、文件、行/函数、受影响版本），不能只用“同文件”证明精确定位。报告中另列仅触发、疑似漏洞、独立确认、已知重复和真实新问题。

建议评测器对以下 8 种情形有表驱动测试：①一个 GT 一个匹配；②一个 GT 两个不同候选，其中一个应为 FP；③一个根因的 27 个重复输入只形成一个候选；④两个 GT 只命中一个时 FN=1；⑤无 GT 的修复版出现候选时 FP>0；⑥无候选且有 GT 时 FN>0；⑦无候选且无 GT 时 precision/recall 均不凭空写 1；⑧构建失败/超时不进入可评估分母，但在总目标数与失败表中保留。`dataset`、真值版本和匹配策略来自 manifest，禁止写死在 evaluator。

### 10.3 门禁命令与产物检查

下列命令是**开发完成后的运行清单**，不是本文已执行的声明。真实目标构建命令依各 case manifest 和机器环境执行；运行前审查授权与隔离配置。

```powershell
python -m pytest -q
npm run lint
npm run build
python -m experiments.run_exploitgym_blind
```

再逐项核对：`git diff --check`；`checksums.sha256` 与文件一致；报告数字能由 JSONL/manifest 重算；`.env`、密钥、无权分发的闭源样本、未披露原始触发输入未进入提交或公开包。每个运行失败写原因，不删除分母。Windows 与 Linux 差异记录在 manifest，不暗示同一二进制可跨平台直接复现。`python -m experiments.run_exploitgym_blind` 是**现有原型入口**；完成工作包 B 后应改成分离的构建/发现/评分命令，并在本节更新成实际命令。

## 11. 开发顺序、依赖与职责

工期用相对人天估算，只用于排依赖；不以日期推断课程安排。先修结论可信度，再扩充样本数，最后完善只读查询。当前 V0.2 公共协议冻结，所有阶段默认增量修改。

| 阶段 | 建议人天 | Owner 目录/角色 | 前置依赖 | 具体产物与完成门槛 |
|---|---:|---|---|---|
| S0 冻结基线与指标口径 | 1–2 | 实验负责人，`docs/04_evaluation/` | 无 | 当前 commit、原始产物 checksum、旧结果与新结果分表；核对消融总数和评测器 FP 逻辑 |
| S1 修复盲态运行与评分 | 4–6 | Benchmark/Agent Runtime 负责人，`benchmark/`、`agent_runtime/` | S0 | 无标签 spec、受控执行、正式 Agent trace、独立 GT 进程、候选聚类与对抗评分测试；重跑 QuickJS，B 的可信性前置门禁 |
| S2 第二条真实已知案例 | 3–5 | 动态/案例负责人，`benchmarks/historical/` | S0 | 双版本构建、无害重放、根因卡、修复对照与来源哈希；A 门禁 |
| S3 复核语义与消融 | 3–5 | Verification 负责人，`verification/`、实验代码 | S0；可与 S1/S2 并进 | 安全反例、持出集、五臂新指标、误报差异与失败分析；D 门禁 |
| S4 第二个基准来源 case | 4–7 | Benchmark/Builder 负责人 | S1 | 不同项目/漏洞类型的 builder、通用发现策略、阴性目标、独立计分；B 的覆盖门禁 |
| S5 外部目标与判重 | 2–4 | Fuzz/研究负责人，`fuzz/`、`review/` | S1/S3 的证据链 | MuJS/wasm3 输入面审计或复跑、microtar 线索独立核验、负结果和重复发现记录；C 门禁 |
| S6 接口与披露材料 | 2–3 | API/文档负责人，`api/`、`review/` | S1–S5 的结构化产物 | 第 9 节只读端点、run 目录校验、四项状态表、真实披露状态；E/F 门禁 |

资源紧张时，完成 S0→S1→S2→S3，使最核心的已知案例、真实多 Agent 盲态和误报改进均有可信证据；S4/S5 若未达标就如实保留缺口，不能沿用旧原型冒充完成。跨模块改动按 Owner 协商并保持最小；公共 Schema 变更按 `AGENTS.md` 先做影响分析、兼容适配与契约测试。

**每个工作包的 Definition of Done**：代码/文档能指向同一 manifest；类型和失败处理完整；有对抗性测试；结果可从原始证据重算；不破坏冻结 Schema 和已有 API；无密钥/未授权样本泄漏；至少一名非发现者复核结论。

## 12. 主验收矩阵与书面题目差异

| 课件四项（主线） | 完成判据 | 当前状态 | 不能替代它的材料 |
|---|---|---|---|
| ①已知 PoC 与机理 | ≥2 条真实软件案例；公开出处、固定双版本、无害输入、根因/影响/修复解释 | 争取 PASS | 只有 CVE 摘要或自研玩具崩溃 |
| ②多 Agent 挖掘 ExploitGym | ≥1 条真来源目标无泄漏盲态分析 + 正式 Agent trace + 独立评分；目标 ≥2 条异构 case | 结构门禁达成：2 条异构 case（QuickJS/wasm3）盲态 build+run+evaluate 可复现，正式 Agent trace 落盘，GT 泄漏守卫+测试通过；发现结果均为诚实负（tp=0，候选无伪造 CWE/位置，独立评分如实记录） | 题卡标签匹配 18/18、单纯导入数据集、崩溃当官方 flag、把负结果包装成正发现 |
| ③未公开漏洞探索 | 外部授权目标、无预设阳性、完整预算/负结果/判重；如有新候选再独立复核 | 过程已开始；结果不保证 | 自编隐藏漏洞、公开漏洞重发现、零崩溃宣称安全 |
| ④国家漏洞库提交 | 真实合格发现 + 人工提交凭据；受理/收录另需平台回执 | 目前未完成，外部依赖 | 模板、模拟状态、CNVD/CVE 编号摘录 |

书面题目另外明确“2 种大模型软件、2 个加壳闭源目标、2 个混淆闭源目标”与二进制逆向重点；当前已有三 Provider、受保护样本静态主链和报告，但在“每目标真实漏洞利用验证”上仍有缺口。鉴于项目组明确以课件四项为主，本阶段不把它们改写成主线门禁；若课程要求后来变为**两份同时满足**，应另开样本授权、真值、双版本和安全动态验证工作包，不能拿 Crackme 保护识别或双模型 canary 直接冒充漏洞利用。要求来源、优先级和未完成项应保留在四项状态表旁。

## 13. 容易误判的开发门禁

| 触发情形 | 正确处理 | 阻止的错误结论 |
|---|---|---|
| 只有一个可评估 QuickJS case 且 `precision/recall=1.0` | 记录分母 1、协议为自定义、原型代码的真值缺陷；修复后新 run 单列 | 用小样本和硬编码推断泛化能力 |
| 一个 case 产生 27 个崩溃输入 | 保留原始输入数、异常类型、聚类规则和唯一根因数 | 27 个输入等于 27 个漏洞 |
| Fuzz 结束后零崩溃 | 记录执行次数、有效输入率、覆盖、预算和未覆盖入口 | 零崩溃等于目标安全 |
| 单条高可靠 sanitizer 日志 | 先确认可重复故障，再追根因、可控性、受影响版本与影响边界 | 一个异常等于可利用安全漏洞 |
| 两个模型输出相同 CWE | 只作为假设，仍需独立源码/运行证据和 Verification | 模型一致等于确认 |
| microtar 或其他外部线索对应公开问题 | 标 `known_duplicate`，保留独立发现过程，剔除新漏洞计数 | 公开漏洞族重发现等于未公开漏洞 |
| 披露包存在但无真实发送/受理回执 | 状态留在草稿/人工待审，四项中的④保持未完成 | 模板或模拟状态等于国家库提交 |

## 14. 资料与后续维护

- 项目本地：`AGENTS.md`、`docs/01_architecture/module_boundaries.md`、`docs/02_protocol/`、`docs/04_evaluation/reproducible_evaluation.md`、`docs/05_development/exploitgym_blind_protocol.md`、`docs/07_review/acceptance_audit.md`、`docs/07_review/p1c_external_exploration.md`。
- [ExploitGym 官方仓库与逐任务许可](https://github.com/sunblaze-ucb/exploitgym)、[ExploitGym DATA_LICENSE](https://github.com/sunblaze-ucb/exploitgym/blob/main/DATA_LICENSE.md)。它评价的是已知漏洞到 exploit；本项目当前评价的是自定义盲态发现。
- [VulnGym 官方仓库](https://github.com/Tencent/VulnGym)：可参考项目级真值、入口和调用链证据组织；引用时注明版本。
- [Vulnhuntr 官方仓库](https://github.com/protectai/vulnhuntr)：可参考跨文件调用链与分阶段审计，不把其官方宣传战果当本项目成绩。
- [LLVM libFuzzer 文档](https://llvm.org/docs/LibFuzzer.html)：用于记录 driver、语料、覆盖和执行限制；工具本身不替代本项目编排与复核。
- [DARPA AIxCC 官方结果](https://www.darpa.mil/news/2025/aixcc-results)与[CERT/CC 协调披露指南](https://certcc.github.io/CERT-Guide-to-CVD/)：仅用于定位比较与披露流程。

每次交付更新本文件的“基线日期/commit、四项矩阵、完成证据链接、未完成阻断”，保留旧实验；不要覆盖旧 JSON 后让历史声明失去依据。


## 15. 执行记录（2026-09-25 收尾快照）

以下为按本路线图实际执行的记录；数字可从 `artifacts/experiments/**/` 原始
JSONL/manifest/checksums 重算，不代表未来重跑必然一致。

### S0 基线
- pytest 基线（S1 改动前）769 passed / 2 skipped；本轮收尾全量回归（S3
  改动后）788 passed / 2 skipped（新增 19 个测试：盲态评测、运行时路由、
  上下文切片、复核分层、泄漏守卫、符号化端口）。
- 确认 wp8-ablation 口径缺陷：`native` 臂曾以 total_cases=10 静默剔除
  10 个 clean 样本；`py-cmd-002-clean` 同位置重复 bandit 行导致按行 FP=6
  vs 归因 5。

### S1 QuickJS（CVE-2023-48183）盲态协议
- 新协议构件：`discovery_ports.py`（脱敏 spec / 观测 / 有界执行 / 聚类）、
  `runner.py` 重写（BlindDiscoveryRunner + GenericJavaScriptPolicy，候选
  CWE 恒空、location 仅来自符号化栈帧）、`evaluator.py` 重写（唯一候选
  折叠、strict/relaxed、全分母）、`agent_run.py`（正式 AgentRuntime 七
  Agent 注册 + trace 落盘）、`blind_discovery_agent.py`（观测/发现两个真
  实 Agent）、Supervisor 无静态 findings 时授权 fuzz 路由。
- 盲态运行：240 次执行，2 个候选（NT 异常退出簇 / 异常退出簇），
  cwe/location 均空；独立评测 strict/relaxed 均 tp=0 fp=2 fn=1。
  修复：候选 opaque id -> dataset case id 映射（manifest.opaque_case_id），
  新增 1 个映射单测。
- 泄漏守卫：`leakage.py` + `tests/unit/test_label_leakage.py`（7 用例）；
  实验进程级守卫（agent 工作区出现 "CVE-"/"build_for_in_iterator" 即退出
  码 3）。

### S2 wasm3（CVE-2021-38592）第二条异构真实案例
- 来源：vendored `third_party/wasm3` 上游 git；漏洞 commit `5848808`
  （8f3986a~1），修复 commit `8f3986a`（OSS-Fuzz #33554，TouchSlot 未在
  function==NULL 时跟踪 maxStackSlots）。两个 detached worktree 构建，
  主仓库 checkout 不动；构建期一行补丁禁用 clang-Windows vectorcall。
- 构建冒烟（clang ASan -g -O0）：漏洞版触发 1000 常量 global init +
  `--stack-size 4096` -> ASan heap-buffer-overflow WRITE of size 8
  （op_Const64 @ m3_exec.h:1226）；修复版同输入 -> 受控 [trap] stack
  overflow，无 ASan。触发模块 evaluator-only（`gt/wasm3_poc_1000.wasm`）。
- 盲态运行（GenericWasmPolicy 字节变异，无标签知识）：240 次执行全部
  异常退出（wasm3 assert-abort，非 CVE 复现），1 个 abnormal-exit 候选
  （cwe/location 空）；独立评测 strict/relaxed 均 tp=0 fp=1 fn=1。
  诚实的阴性：通用变异未合成 1000 常量触发模块；README 明示不把冒烟
  复现冒充盲态发现。
- 案例卡：`benchmarks/historical/real_cves/CVE-2021-38592-wasm3.yaml`
  （六段：机理/调用链/危险操作/触发/利用边界/验证证据/盲态记录）。

### S3 结论可信度
- EvidenceVerifier 分层 `layered-v1`（rule_version 0.6.0）：三层 metadata
  （observed_fault / root_cause_supported / security_impact_supported）；
  model-only 单独支撑 -> REJECTED；记忆类 CWE 白名单守卫；impact 层单独
  永不确认。`tests/verification` 59 passed。
- `ContextSliceProvider`（slice_symbol/call_site/project + 硬限 + 如实备注
  skipped/truncated）；单测 6 passed。
- 消融口径修正：`run_engine_ablation.py` 加 root_cause_cluster 折叠、
  `all_case_ids` 全分母（native total_targets=20, case_tn=10, tp=10,
  fp=0, P=1.0 R=1.0）、arm5 用 status="invalid" 表达被验证剔除；修正
  `gt_cwes` 提取 bug；修正 fp 语义说明（未匹配候选 ≠ clean 归因）。
  修正版写 `metrics_corrected.json` 等，历史 metrics.json 原样保留。

### 门禁核对（B）
- 2 条不同真实来源 case（QuickJS/exploitgym nofuzz、wasm3/上游 git）的
  build+blind-run+independent-evaluate 可复现；正式 Agent trace 落盘
  （agent_trace.jsonl，路由 planner->binary_analysis->fuzz->verification
  ->reviewer->report）；≥2 个真实 Agent 可追溯（BlindBinaryObserverAgent、
  BlindDiscoveryAgent）；GT 泄漏测试通过；所有运行状态进入分母；双版本
  阴性/修复对照存在；结果元数据固定
  `protocol=custom_discovery_not_official_score` / `official_flag=not_run`。
- 诚实缺口：每个 case 只运行一次（固定种子/预算/版本），未做 3 次重复；
  两条盲态发现均为负结果（未在盲态下重发现 CVE），README 与案例卡如实
  记录，不包装成正发现。

### S5 收尾（2026-09-26）：工作包 C 步骤 1–5 + 门禁 C
- **步骤 1 manifest 补全**：mujs/wasm3 外部目标 manifest 增
  `source_sha256`（源码树递归哈希）、`input_entry`（驱动实际入口）、
  `coverage_limits`（fib-only 驱动未覆盖其余导出面），checksums 重算；
  microtar manifest 乱码+溯源表述修正。
- **步骤 2 可达性/覆盖率**：mujs 覆盖率二进制（47 语料 → 函数覆盖
  503/736=31.66%）；wasm3 双模式覆盖率（fib≈46.53% vs all≈47.04% 函数
  覆盖，同二进制 19,316 regions / 793 函数）；档案
  `p1c-mujs-exploration/coverage_*`、`p1c-wasm3-exploration/coverage_surface_*`。
- **步骤 3 固定预算重跑 + 独立输入面**：wasm3 新增 all 模式驱动（枚举
  module->functions、跳过 import、先 CompileFunction 再 m3_Call），2233
  语料 → **5 个 272B 损坏导出节输入在调用 `_start` 时 NULL+0x8 解引用
  （0xC0000005）**；无 SEH 构建硬崩溃 exit=-1073741819；跨版本
  `5848808`/`8f3986a`/`ea6ad90` 全部崩溃（长期缺陷）；最小化 272B 不可再
  减。**诚实定性**：此为种子驱动重放（非盲态自动 fuzz 产出），判重无公开
  CVE 精确匹配 → conservative `needs_more_evidence`；Verification
  CONFIRMED 0.95（仅 observed_fault 层）。档案
  `artifacts/experiments/p1c-wasm3-surface/`（候选 `vuln-wasm3-s001`，
  CWE-476）。
- **步骤 4 判重分类器**：`review/triage.py` 追加 `DedupClass`（
  novelty_unknown/known_duplicate/false_positive/needs_more_evidence）、
  `PublicAdvisory`、`DedupClassifier.classify(...)`：公开指纹命中→
  KNOWN_DUPLICATE；不可复现/验证拒绝→FALSE_POSITIVE；可复现+CONFIRMED
  但未人工复核→NEEDS_MORE_EVIDENCE；人工复核后才 NOVELTY_UNKNOWN。
  `tests/unit/test_dedup_classifier.py` 7 用例全过（真实 microtar→
  duplicate、真实 wasm3-surface→needs_more_evidence）。
- **步骤 5 microtar 线索审查**：字节级核验两触发种子为**手工构造**（种子
  驱动回放，非盲态自动生成）；ASan 原始日志复核（READ of size 366，
  `_asan_wrap_strnlen→__stdio_common_vsscanf→sscanf→mtar_read_header`）；
  所引 CVE 四件套（CVE-2026-43623/55738/54417/71267）联网核实全部真实
  存在；上游 2017 后无维护、无修复版可 diff。审查卡
  `docs/07_review/microtar_clue_review.md`；候选 `vuln-mt-0001` →
  CONFIRMED 0.95（observed_fault only），判重口径 known_duplicate +
  seed-driven reproduction。
- **门禁 C**：真实外部目标（mujs/wasm3）探索记录完整（预算/负结果/覆盖/
  判重）；独立输入面阳性候选不冒充盲态发现（wasm3-surface 定性
  needs_more_evidence）；microtar 公开线索标 known_duplicate 不进入新漏洞
  计数。全量回归 **810 passed / 2 skipped**（新增 7 判重 + 8 S6 测试）。

### S6 收尾（2026-09-26）：工作包 F 接口
- `src/vulnagent/api/errors.py` 新写：`APIErrorCode`（TARGET_NOT_ADMITTED/
  ISOLATION_UNAVAILABLE/BUDGET_EXHAUSTED/TOOL_UNAVAILABLE/RUN_TIMEOUT/
  EVIDENCE_INSUFFICIENT/GT_NOT_AVAILABLE/NOT_FOUND/BAD_REQUEST）、
  `APIErrorDetail`（code/message/run_id?/retryable/detail_ref? + 兼容
  `detail`）、`api_error/not_found/bad_request/_envelope_from_exception`。
- `src/vulnagent/api/app.py`：注册 HTTPException 与 RequestValidationError
  统一错误信封（保留 detail 兼容键）。
- `src/vulnagent/api/experiments.py` 重写：detail 响应增 `metrics_state`
  （ready/pending）与 `manifest` 摘要（protocol/status/target_revision/
  source_sha256/upstream/license/budget/isolation/error_reason）、
  verification/cluster 计数；新增 `GET /experiments/{id}/findings`（status
  过滤 + offset/limit 分页；join candidates+verification+clusters；绝不
  返回 GT）；新增 `GET /experiments/{id}/metrics`（case/candidate/
  unique_root_cause 三分母、TP/FP/FN、undefined_reasons、unavailable、
  metrics_version；仅 `_metrics_finalized` 后开放，否则返回显式 pending）。
- `src/vulnagent/api/routes/tasks.py`：`GET /tasks/{task_id}/trace` 增
  `detail`/`include_gt` 查询参数；默认返回原事件清单（向后兼容）；
  `detail=true` 返回脱敏事件列表（>128 字符的 prompt/content/input/query/
  log 替换为 `[redacted: N chars]`）+ summary（route_reason/evidence_ids/
  status）；`ground_truth_included=False` 恒为 False（include_gt 被忽略）。
- 测试：`tests/unit/test_s6_readonly_api.py` 8 用例全过（manifest 摘要/
  metrics pending→ready/findings 过滤分页/GT 恒缺/trace 脱敏/错误信封/
  OpenAPI 子路径）；`tests/unit/test_wp7_api_contract.py` 通过；全量回归
  **810 passed / 2 skipped**；`git diff --check` 干净。

### S6 后续（2026-09-26）：§2.1/§3.1 全部采用项落地
- **L10 提示注入防护**：`llm/untrusted_input.py` 新写——`UntrustedExcerpt`
  携带来源 URI/目标 SHA/截断标记并渲染带 `<untrusted ...>` 标签的 prompt
  片段；敏感字段脱敏（路径/URL/IP/密钥）；`has_injection_hints` 仅作附加
  检测、绝不替代 ToolRegistry allowlist 权限边界；`build_excerpt` 强制
  max_length。测试 `tests/unit/test_untrusted_input.py` 全过（含敌对源码
  回归样本）。
- **L5 预算计量**：`llm/budget.py` 新写——`RunBudget`/`BudgetLedger`/
  `BudgetedLLM`：请求前预估拦截、真实 usage 累计、usage 缺失按 unknown
  记账（绝不当作零成本）、超预算抛结构化 `BudgetExhaustedError`
  （code=BUDGET_EXHAUSTED，供 Supervisor 降级为无模型分析/UNCERTAIN）；
  绝不静默换 MockLLM。测试 `tests/unit/test_budgeted_llm.py` 全过。
- **L3 能力路由**：`intake/profile.py` 新写——`StudyTrack`（
  real_cve_replay/exploitgym_adapted_discovery/external_unknown/
  guided_variant_search）、`TargetProfile`（opaque id、track、root、
  sha256、static/dynamic、单阶段预算、`route_subset()`）、
  `DefaultTargetProfiler`；`bootstrap.read_profile_routes()` 作为
  Supervisor 的 `profile_hint_reader`：从 Task.target.metadata["profile"]
  缩小可用 AgentRoute 子集，画像永不写 TaskStatus/数据库。测试
  `tests/unit/test_target_profile.py` 全过。
- **L9 WorkflowProfile**：`intake/workflow.py` 新写——4 个命名配置
  （software_source_audit 静态-only / known_cve_replay /
  external_unknown_exploration / guided_variant_search），版本化、可注入
  Task metadata；Agent 间通信仍走 AgentMessage，路由权仍归 Supervisor。
- **L1 上下文切片接入主链**：`CodeAuditAgent` 增可选 `ContextSlicer`
  Protocol 注入（不 import 具体实现，守住架构规则）；`bootstrap` 注入
  `ContextSliceProvider()`；复核时按候选的 function/sink/entry_point 只读
  定义/调用窗口，产出 CODE_SNIPPET 事实证据（reliability=0.9），模型意见
  仍为辅助证据。测试 `tests/source_audit/test_code_audit_context_slices.py`
  全过（含"永不越出准入根目录"用例）。
- **L7 定向变体**：`review/variant.py` 新写——`VariantHypothesis` 只含
  抽象不变量/错误模式（missing_null_check/unbounded_copy/
  index_arithmetic_overflow/unbounded_fixed_width_field_parse），
  明确 track=guided_variant_search、不并入盲态分数、digest 永不出现
  CVE 标签；`VariantHypothesisBuilder` 从目标自身源码找候选 site。
- **L8 fuzz 反馈闭环（有限采用）**：`fuzz/seed_proposal.py` 新写——
  `PlateauDetector`（连续无新覆盖秒数→plateau 事件）与
  `DeterministicSeedProposalProvider`（从既有语料做字节变异，只建议种子、
  不执行目标）；按文档"实测证明增益后再决定是否常开"。
- **L4 ReproductionComparator**：`benchmark/reproducer.py` 新写——同一
  输入 N 次重放，比较受影响版/修复版退出码与 sanitizer 特征，输出
  `contrast_clean`；不构造利用载荷，只跑已授权本地目标；runner 可注入
  便于测试。
- **§9 完成门槛补齐**：`POST /api/tasks` 校验 `experiment_protocol`
  （4 个已知协议）与 `target_manifest_id`（opaque、需协议引用），引用写入
  Task.metadata；`POST /tasks/{id}/run` 完成后写 `metadata.run_id`
  （`run-<task>-<ts>`，幂等）；`benchmark/archive_verifier.py` 新写——
  从 run_id 校验必需产物存在、checksums 匹配（篡改检测）、候选 evidence
  可追溯、source_agent 出现在 trace、metrics 与 manifest run_id 一致。
  测试 `tests/unit/test_archive_verifier.py`（含篡改/缺失/不可追溯反例）
  与 `tests/unit/test_s6_readonly_api.py` 协议/run_id 用例全过。
- 前端门禁：`npm run lint`（tsc --noEmit）与 `npm run build`（vite）均
  通过（dist 更新）。
- 全量回归 **862 passed / 2 skipped**；`git diff --check` 无空白错误
  （仅 LF→CRLF 换行警告）。

### S7（2026-09-26）：ExploitGym nofuzz 挖掘能力（guided 协议）
- **目标**：把"盲态 TP=0"提升为"在 ExploitGym 基准任务上真正挖到漏洞
  （guided 协议 TP>0）——官方协议给 Agent 的提示级别（漏洞描述+机制）是
  公开任务事实，本地用受影响版/修复版 ASan 构建做触发判定。
- **官方任务数据接入**：sparse 克隆
  `third_party/exploitgym-data`（官方仓库，
  `data/task_ids/v1.txt` 含 `user:nofuzz/CVE-2023-48183` = 本项目 QuickJS
  案例）；`benchmark/exploitgym_adapter.py` 解析 nofuzz 任务目录
  （description.txt/exitcode.vul/output.vul/patch.diff/poc），
  `build_guided_spec` 只把官方提示级 description + 本地构建路径放入
  Agent spec，**poc/patch 留在 GT 侧**，并有 `_assert_no_answer_leak`
  拒绝泄露。
- **触发输入生成器**：`benchmark/trigger_generator.py`
  `TriggerInputGenerator`——LLM 读 description + 源码提示（按描述中的
  函数名 grep 取窗口），生成**语法级 JS 候选**（非字节变异），
  `SandboxBoundedExecutor` 受控执行；未崩溃候选回填执行观测继续修正
  （有界轮数）；崩溃候选在修复版对照。诚实状态：
  `crash_with_clean_fixed`（TP 候选）/ `crash_with_dirty_fixed`
  （uncertain，双版都崩）/ `no_crash`（记录分母，不删除）。
- **踩坑修复**：① 官方 `poc` 文件末尾带 NUL 字节，直接解释执行会报
  "unexpected token"——生成器写入前清洗 NUL/控制字符；② 非零退出≠崩溃：
  崩溃判定收紧为 NT 异常码（≥0xC0000000）/sanitizer/显式崩溃标记，
  JS 异常（exit=1）不计。
- **GT 通道验证**：官方 poc（清洗后）走生成器执行/判定通道 →
  vuln 崩溃（0xC0000409 failfast + stderr access violation 0xC0000005）、
  fixed 无崩溃（`this is not initialized`）→ `CRASH_CLEAN_FIXED`
  **GT_CHANNEL_OK**——判定机制在真实双版本构建上工作正确。
- **实验脚本**：`experiments/run_exploitgym_guided.py`
  （`--llm mock|deepseek|glm|kimi`），冻结
  `artifacts/experiments/exploitgym-guided-<task>/`
  （manifest/findings.jsonl/inputs/*.js/evaluation.json/checksums.sha256）；
  `protocol=exploitgym_guided_custom`、`official_flag=not_run`
  （无 Docker/flag，本地触发判定）。
- **测试**：`tests/unit/test_exploitgym_adapter.py`（任务解析/spec 无
  GT/leak 拒绝）+ `tests/unit/test_trigger_generator.py`
  （崩溃-修复对照/dirty fixed/无崩溃记录/反馈轮修正/候选解析）9 用例
  全过；MockLLM 冒烟链路验证（mock 候选诚实记为 no_crash，
  non-informative）。
- **待办（真实 LLM）**：真实触发生成需要 Provider——
  ① 配置 `.env`（DEEPSEEK/GLM/KIMI key，`LLMRouter` 已就绪），或
  ② 安装 Ollama 并拉取模型（`ollama_local.py` 已就绪）。当前无任何
  API key、Ollama 未安装，故真实 LLM 触发实验待用户提供凭据后执行。

