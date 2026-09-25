# 实践要求严格审核与改进文档

审核对象：VulnAgent 课程设计项目（WP0–WP8 已完成，门禁 753 passed / 2 skipped）
审核依据：课程 PPT《实践内容思路》「漏洞挖掘类实践」4 条要求 +「渗透测试类实践」4 条要求
审核方法：逐条对照仓库现状（代码/产物/文档路径为证据），给出满足度判定与可执行改进路线。

---

## 一、审核结论总览

| 要求 | 满足度 | 一句话结论 |
|---|---|---|
| 1. 收集已知漏洞 POC，分析触发原理和利用原理 | 🟡 部分满足 | 机理分析框架成立，但样本为自研教学复刻、无真实 CVE POC、缺利用原理维度 |
| 2. 多智能体系统挖掘 ExploitGym 基准集漏洞 | ❌ 未满足（框架半步） | 仅有"适配筛选层"，未真实接入 ExploitGym 任务、未跑真实挖掘 |
| 3. 多智能体系统挖掘未公开漏洞 | 🟡 框架满足 | 未知目标探索流程完整，但未在真实未公开目标上产生发现 |
| 4. 提交国家漏洞库 | 🟡 流程就绪 | 披露状态机 + 未提交声明存在，缺提交材料包与条件清单 |
| 渗透 1/4. 针对非法网站开展测试 | ⛔ 合规红线 | 未授权攻击第三方目标属违法行为，不可执行，不提供指引 |
| 渗透 2/3. LLM 渗透工具收集 / 多智能体自动化渗透 | ⚪ 未覆盖（可合规扩展） | 文献调研可合规完成；自动化渗透仅限自建/书面授权靶场 |

**总体判定**：架构级能力（多智能体编排、盲评基准、真实动态验证、披露管线、
Evidence 全链）全部就绪且质量高；对照照片要求，**实质性差距集中在"真实
材料 / 真实基准"**——真实 CVE POC、真实 ExploitGym 接入、真实未公开目标、
国家漏洞库提交材料。这是典型的"框架强、实料缺"差距，改进路线见第三节。

---

## 二、逐条差距分析（含证据）

### 要求 1：收集已知漏洞的 POC，分析漏洞触发原理和漏洞利用原理

**现状**：`benchmarks/historical/case_cards/` 已建 3 个机理分析案例卡
（cp_parse CWE-121、py-cmd-001 CWE-78、py-sql-001 CWE-89），每卡记录
入口 → 调用链 → 危险操作 → 触发条件 → 无害复现 → 修复对照；分析文档
`docs/06_presentation/case_studies.md`。

**差距**：
- 案例全部为**自研教学复刻 fixture**（每卡 `upstream_advisory: none`），不是
  "收集已知漏洞的 POC"——无真实 CVE 编号、无公开 POC 文件、无上游修复提交引用。
- 仅分析**触发原理**（为何崩/为何注入）；**未分析利用原理**（如何从触发到
  达成越权/代码执行/数据泄露的完整利用链）。AGENTS.md 将"真正漏洞利用"列为
  V0.2 不要求项——这是设计边界，但照片要求明确含"利用原理分析"，需补齐
  **理论级利用链分析**（不需真实 exploit 开发，分析即可）。

**证据**：`benchmarks/historical/case_cards/*.yaml`（source/pinned_revision/
upstream_advisory 字段）；`docs/06_presentation/case_studies.md`（无 exploitation 章节）。

### 要求 2：编写多智能体系统，挖掘 ExploitGym 安全基准测试集的漏洞

**现状**：多智能体系统本身完整（WP0–WP7）。ExploitGym 侧只有：
- `src/vulnagent/benchmark/adapters.py` 的 `ExploitGymDiscoveryAdapter`（四维
  筛选：本地可固定目标/GT 可分离/答案隐藏/可安全运行）；
- `benchmarks/blind/exploitgym_candidates.yaml`：4 条**模拟筛选输入**
  （文件自注 `simulated screening inputs; real task data requires upstream
  DATA_LICENSE review`）；
- `experiments/run_blind_evaluation.py` Track A：对上述候选跑筛选并记录
  资格决策，明示"自定义协议，绝不冒充官方 ExploitGym 分数"。

**差距**：**未真实接入 ExploitGym 基准测试集**——未安装/拉取官方基准、
未将真实任务注册为本地目标、未在真实任务上运行发现管线、无任何官方口径
指标。当前状态是"筛选层就绪"，离"挖掘 ExploitGym 漏洞"差一个真实接入层。

**证据**：`benchmarks/blind/exploitgym_candidates.yaml`（note 字段）；
`adapters.py`（`non-official by design` docstring）；`run_blind_evaluation.py`
Track A 仅产出 `screening.jsonl`。

### 要求 3：编写多智能体系统，挖掘未公开的漏洞

**现状**：WP6 已交付完整"未知目标探索"框架：目标选择（`practice_mode`）、
脱敏卷宗（`src/vulnagent/review/dossier.py`）、三分类 triage、披露状态机
（CANDIDATE→REVIEW→…→DISCLOSED/UNSUBMITTED）、诚实声明
`Nothing has been submitted`。动态侧有真实 libFuzzer/ASan 闭环可复现。

**差距**：所有探索目标仍是**自研教学样本**（benchmarks/ 下），未在任何
**真实未公开目标**（授权开源软件历史版本 / 自己编写的未公开程序）上走完
一次完整卷宗流程。课程内不虚构零日是正确的，但"流程就绪"与"真实执行"
之间有可合规弥合的中间地带（见改进路线 P1）。

**证据**：`benchmarks/` 全量样本 `source: VulnAgent self-authored teaching fixture`；
`experiments/run_unknown_exploration.py` 的输入 catalog 来自自研 blind 目录。

### 要求 4：提交国家漏洞库

**现状**：WP6 披露状态机含 `UNSUBMITTED` 终态与"未提交"声明；无任何
CNNVD/CNVD 提交材料。

**差距**：缺**提交材料包模板**（漏洞描述 / 危害等级 / 影响版本 / 修复建议 /
验证步骤 / 复现材料）与**提交条件清单**（谁可提交、什么构成有效漏洞、
CNVD 收录标准、授权与伦理前置检查）。流程状态机在，落地材料不在。

**证据**：`src/vulnagent/review/dossier.py`（披露状态字段）；
`experiments/run_unknown_exploration.py`（`Nothing has been submitted`）。

### 渗透测试类要求（4 条）——合规判定

- **渗透 1「针对非法网站，开展手动信息收集和测试」**：⛔ **不可执行**。
  对未授权第三方网站开展信息收集与测试属于《网络安全法》第 27 条、
  《刑法》第 285/286 条规制的未授权访问/破坏行为。本审核不提供此类指引。
  合规替代：本地自建靶场（DVWA / Metasploitable / 自有代码）或持有
  书面授权的目标。
- **渗透 2「收集分析基于 LLM 智能体的开源自动化渗透测试工具」**：⚪ 属
  文献调研，可合规完成；本项目范围聚焦漏洞挖掘，未覆盖，列为可选扩展。
- **渗透 3「编写多智能体系统，开展自动化渗透测试」**：⚪ 系统架构可复用
  （多智能体编排 + 工具适配层），但仅允许对**自建靶场/书面授权环境**执行；
  需新增授权边界校验与靶场供应模块。
- **渗透 4「针对非法网站，开展基…」**：⛔ 同渗透 1，不可执行。

> 结论：渗透测试类中两条"针对非法网站"要求超出合规边界，**不纳入改进
> 计划**；如教师要求展示，建议在答辩中主动说明合规红线与替代路径。

---

## 三、改进路线（按优先级，全部可运行/可复现）

### P0-1：真实接入 ExploitGym 基准集（命中要求 2）

1. 拉取 ExploitGym 官方基准（`pip install exploitgym` 或 git clone），
   先做 `DATA_LICENSE` 与本地可运行性审核（沿用现有
   `ExploitGymDiscoveryAdapter` 四维筛选，逐个任务记录资格）。
2. 新增 `experiments/run_exploitgym_discovery.py`：对**筛选为 eligible 的
   真实任务**运行现有多智能体发现管线（native + semgrep + bandit 静态、
   libFuzzer/ASan 动态），候选写入标准 `VulnerabilityCandidate` JSONL。
3. 复用 `BlindEvaluator` 输出 TP/FP/FN/Precision/Recall；报告**同时**给出
   "官方口径可复算数"与"自定义协议数"两列，绝不混称。
4. 门禁：新增 `tests/unit/test_exploitgym_adapter.py`（真实任务登记 +
   筛选决策 + 发现管线冒烟）。

### P0-2：真实 CVE 案例卡 + 利用原理章节（命中要求 1）

1. 选 2–3 个有公开 POC 的历史 CVE（如公开仓库可复现、授权清晰的
   教学级案例，示例：CVE-2019-… 等需在实现时按"公开 POC + 许可"筛选）。
2. 每个案例卡补字段：`cve_id`、`upstream_advisory_url`、`poc_source`、
   `fixed_commit`；样本以 git submodule/pinned 方式固定版本。
3. 案例卡新增 **利用原理（Exploitation Analysis）** 章节：从触发到
   越权/代码执行/数据泄露的完整利用链（理论级分析，不含可运行 exploit
   载荷；遵循 AGENTS.md「不自动生成攻击载荷」边界）。
4. `docs/06_presentation/case_studies.md` 增加「真实案例对照」节，与
   自研复刻案例并列，标明来源与授权。

### P1-1：授权真实目标的"未知探索"示范（命中要求 3）

1. 选一个**明确授权、可本地复现**的目标（如：自研的未发布工具、或
   教师提供的练习程序；不使用公网未知目标）。
2. 走完 WP6 全流程：目标选择 → 静态/动态发现 → 脱敏卷宗 → triage →
   披露状态机 → 终态 `UNSUBMITTED`（诚实声明）。
3. 产物固化到 `benchmarks/unknown/` + 卷宗 `artifacts/dossiers/`，作为
   答辩可复现演示。

### P1-2：国家漏洞库提交材料包（命中要求 4）

1. 新增 `docs/07_review/`（本目录）下 `disclosure/` 提交材料模板：
   `cnvd_submission_template.md`（漏洞描述/危害等级/影响版本/复现步骤/
   修复建议/验证材料清单）。
2. 新增提交条件检查清单（授权与伦理前置、漏洞有效性标准、CNVD 收录
   流程、谁有权提交）；流程仍保持 `UNSUBMITTED` 诚实状态，不虚构提交。

### P2：渗透测试类合规扩展（可选）

- 文献调研（渗透 2）：新增 `docs/07_review/llm_penetration_tools_survey.md`，
  收集分析开源 LLM 渗透工具（合规口径，仅调研不实施）。
- 自动化渗透（渗透 3）：若时间允许，复用现有 Agent/Tool Registry 构建
  **靶场限定**渗透编排，硬编码授权边界（仅 `local://` 或白名单靶场）。

---

## 四、验收口径（改进完成后如何判定满足）

| 要求 | 验收标准 |
|---|---|
| 1 | 每案例卡含 `cve_id` + `upstream_advisory_url` + `poc_source` + 利用原理章节；至少 2 个真实 CVE 案例 |
| 2 | `python -m experiments.run_exploitgym_discovery` 在 ≥2 个 eligible 真实任务上产出候选与指标；报告区分官方口径/自定义协议 |
| 3 | 至少 1 个授权真实目标走完卷宗全流程，产物可复现，终态诚实 |
| 4 | 提交材料模板 + 条件清单存在于 `docs/07_review/disclosure/` |
| 渗透 1/4 | 不实施、不提供指引；答辩话术含合规边界说明（见 `docs/06_presentation/demo_routes.md`） |

## 五、合规与伦理声明

- 本审核不认可、不提供任何针对未授权第三方系统（照片所称"非法网站"）
  的测试方法；该类行为违反中国法律，任何实现都必须限定在自建/书面授权
  目标内。
- 所有漏洞样本保持在本地、自研、明确授权范围；披露保持诚实状态机，
  不虚构提交、不夸大发现。
