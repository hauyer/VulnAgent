# WP8 — 收尾：案例卡、完整消融与误报分析、最终文档包

对应开发指导书第 13 节与成果线 A/B/C 的测量环节。本工作包是课程设计
的收尾交付，全部产物可复现、可演示。

## 1. 机理分析案例卡（成果线 A）

目录 `benchmarks/historical/case_cards/`（3 个 YAML）：

- `cp_parse-vuln.yaml`：CWE-121 栈越界（动态证实，crash + 修复对照 clean）
- `py-cmd-001-vulnerable.yaml`：CWE-78 命令注入（静态，对照 py-cmd-002-clean）
- `py-sql-001-vulnerable.yaml`：CWE-89 SQL 注入（静态，参数化修复）

每个案例卡记录：CWE、入口、调用链、危险操作、触发条件、无害复现命令、
固定版本/修复版本、授权声明（static_read/dynamic_run）。
机理分析文档：`docs/06_presentation/case_studies.md`。

> 诚实声明：三个案例均为自研教学复刻 fixture（无真实 CVE/上游公告），
> `upstream_advisory: none` 已在卡内标注。

## 2. 完整消融与误报分析（成果线 B/C 测量）

实验器 `experiments/run_engine_ablation.py`（可复现：
`python -m experiments.run_engine_ablation`）。

- **对象**：`benchmarks/manifest.json` 20 个自研 L0 source 样本
  （10 vulnerable + 10 clean，仅静态只读分析）。
- **5 个消融臂**（同一批样本、独立评测）：
  1. native（自研 PythonSourceAuditor）
  2. native + semgrep
  3. native + bandit
  4. native + semgrep + bandit（全量发现）
  5. 全量 + 验证（CWE 白名单代理）
- **评测**：每臂用 WP5 `BlindEvaluator` 独立重算 TP/FP/FN/Precision/Recall；
  clean 样本的告警作为真实 FP 计入分母，不删失败行。

### 结果（artifacts/experiments/wp8-ablation/metrics.json）

| 臂 | total | TP | FP | FN | Precision | Recall |
|---|---|---|---|---|---|---|
| native | 10 | 10 | 0 | 0 | 1.0 | 1.0 |
| native+semgrep | 10 | 10 | 0 | 0 | 1.0 | 1.0 |
| native+bandit | 12 | 10 | 6 | 0 | 0.625 | 1.0 |
| full | 12 | 10 | 6 | 0 | 0.625 | 1.0 |
| full+verification | 12 | 10 | 6 | 0 | 0.625 | 1.0 |

### 误报归因（fp_attribution）

| 引擎 | clean 样本上的位置级 FP |
|---|---|
| native | 0 |
| semgrep | 0 |
| bandit | 5（py-cmd-002×2、py-cmd-004×3，均为通用 subprocess 规则） |

### 结论与失败案例

1. 自研 native 规则在 L0 上 P=R=1.0；Semgrep 无新增信号（其对教学样本的
   告警与 native 重叠）。
2. Bandit 引入 5 个唯一误报（候选级 6 条），全在 clean 命令包装样本上，
   规则为通用 `subprocess` 告警（B602/B603 类），对 `shell=False` 修复样本
   依然报警。
3. **验证臂的局限（诚实记录）**：真实 Bandit FP 的 CWE（CWE-78）与 GT
   集合重合，规则级 CWE 白名单验证无法剔除它们 → 这正是 WP3 独立复核
   （ReviewerAgent + 证据校验）存在的理由；WP5 盲评的 3×FP 与此同源。
4. 无 invalid/excluded 行；所有目标文件存在，无引擎 unavailable。

## 3. 最终文档包

| 产物 | 位置 |
|---|---|
| 路线总览（WP0–WP8） | `docs/06_presentation/demo_routes.md`、`docs/06_presentation/case_studies.md` |
| WP 文档 | `docs/05_development/wp{2..8}_*.md` |
| 消融产物 | `artifacts/experiments/wp8-ablation/{summary,metrics,ablation_metrics}.json` + candidates/ + ground_truth/ |
| 前端展示 | UI「实验」页显示 `wp8-ablation`（只读研究 API） |
| README | 见仓库根（运行/演示入口） |

## 门禁

- `python -m pytest -q`：全量通过（含本轮 `evaluator.py` 空行跳过与
  GT 行 0 语义改动回归）。
- `cd frontend && npm run lint && npm run build`：前端构建通过。
