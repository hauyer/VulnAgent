# WP6 — 未知探索与脱敏卷宗

## 目标（开发指导书 WP6 / L5 / 建议作品 C）

面向**授权未知目标**（exploratory 模式，无预设正例）提供系统化研究过程：
发现 → triage → 历史知识去重 → 人工复核标记 → 脱敏报告草稿与披露状态机。
核心红线：**未经独立确认，引擎不生成"新漏洞已发现"结论**；负结果如实记录，
但 exploratory 轨绝不把"未发现"计算成 TN；卷宗只保留摘要与哈希，
敏感内容与未公开发现不进公开报告/Git。

## 新增模块

- `src/vulnagent/review/dossier.py`
  - `ExploratorySession`：会话（授权四维、manifest 哈希、工具版本、预算、
    随机种子、开始/结束时间、停止原因、观察日志、回执）。
  - `DossierState` 披露状态机：`draft → maintainer_contacted → submitted →
    acknowledged → fixed → published/accepted`；只能前进、由**人工回执**驱动，
    系统不自动对外提交；`practice_mode` 上限为 submitted（课程演练明确标注未提交）。
  - `ExplorationLogEntry`：阶段 discovery / triage / verification / **negative**。
  - `redact()` → `RedactedDossier`：剥离触发输入/内部路径/敏感描述，
    候选引用只留末 16 位指纹，保留计数与时间线，附"未提交"披露说明。
  - `DossierStore`：JSON 持久化。
- `src/vulnagent/review/triage.py`
  - `HistoricalKnowledgeDedup`（CVEfixes/上游公告/CWE 知识表）：
    `duplicate_known`（指纹命中已知问题）/ `needs_human_review`（无匹配，
    引擎不自行宣称新颖）/ `insufficient_evidence`（无证据）。
  - `negative_note()`：负结果标记 `counted_as_tn=false` + 原因。
- `src/vulnagent/api/dossiers.py` — 研究 API：创建会话、追加观察、记录回执、
  状态推进（非法转换 422）、脱敏草稿（缺失 404）。
- `experiments/run_unknown_exploration.py` — 授权未知目标探索实验器。

## 实测结果（本机）

三个授权未知目标（自研教学样本充当未知，无预设正例）：
- `py-cmd-001-vulnerable`（CWE-78）：4 候选全部 **duplicate_known**
  （历史知识表含 subprocess 已知问题）→ 无新颖候选 → 记负结果。
- `cp_parse-vuln`（CWE-121，真实 libFuzzer/ASan 崩溃）：不在知识表 →
  **needs_human_review**（唯一待人工复核候选，引擎不下"新漏洞"结论）。
- `py-cmd-002-clean`（Bandit 误报 3 条）：2 条 duplicate_known、
  1 条 needs_human_review（待人工判定）。

卷宗（`dossier_redacted.yaml`）：`practice_mode=true`、状态 `draft`（演练可推进至
maintainer_contacted，禁止继续）、候选指纹 3 条、负结果 1 条、披露说明
"Nothing has been submitted"。triage/候选/会话均落盘
`artifacts/experiments/wp6-exploration/`。

## 复现命令

```bash
python -m experiments.run_unknown_exploration
# 产物：artifacts/experiments/wp6-exploration/
#   candidates.jsonl  triage.jsonl  dossier_redacted.yaml  summary.json  dossiers/*.json
```

## 测试

- `tests/unit/test_dossier_state_machine.py`（7 项）：状态机仅前进、
  practice 模式上限、回执显式记录、脱敏（指纹保留/敏感剥离/待复核计数）、
  triage（已知去重/新颖需人工/证据不足）、负结果不计 TN。
- `tests/unit/test_dossier_api.py`（2 项）：研究 API 生命周期 + 404/422。
- `tests/integration/test_unknown_exploration_loop.py`（2 项）：真实审计链路
  闭环（已知模式去重、无新颖断言、状态机约束、持久化）；负结果语义。
- 全量门禁 `python -m pytest -q` 合并前复跑。

## 边界（写进有效性威胁）

- 本实验为课程演练：全部目标为自研样本，卷宗明确"未提交"，无任何
  真实维护者/平台回执；对外披露流程（CNVD/CNNVD/CERT 指南）仅作流程参考。
- "新颖候选"只是待复核标记，不是漏洞判定；人工复核一致率是后续 L5 指标。
