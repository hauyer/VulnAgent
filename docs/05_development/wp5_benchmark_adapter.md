# WP5 — 基准适配：盲评协议（ExploitGym 筛选 / VulnGym 清单 / 独立评测器）

## 目标（开发指导书 WP5 / 7.2-B）

把基准从「教学回归」升级为**标签隔离的项目级盲测协议**：
- ExploitGym 改编**筛选器**：判定任务能否隐藏答案并安全本地运行；不能隐藏/不安全
  的任务只作案例研究，绝不进入盲发现统计，也绝不伪报官方分数。
- **VulnGym/JULIET 清单**：按项目划分 dev / held-out（同项目相邻版本不跨轨）。
- **独立评测器**：`metrics.json` 只能由评测脚本从原始候选行 + 隐藏标签重算，
  不允许手工维护；TP/FP/FN、原始分母、定位误差、失败样本单列。

## 新增模块（自研，未触碰冻结契约）

- `src/vulnagent/benchmark/schema.py`
  - `BlindCaseManifest`：Agent 可见清单（构建/授权/预算；**无任何答案**）。
  - `GroundTruth`：评测侧标签（类型/CWE/位置/触发输入/修复 commit/补丁提示/人工核验）。
  - `EvaluationResult`：重算指标 + `write_metrics()` 只由脚本调用。
- `src/vulnagent/benchmark/leakage.py` — `LabelLeakageGuard`
  - 硬泄漏（trigger、commit、patch、location、独特描述短语、GT 路径）→ 判失败；
    通用 CWE 知识（如 "CWE-"、"stack-buffer-overflow"）→ 记录为知识重叠、不算泄漏。
- `src/vulnagent/benchmark/evaluator.py` — `BlindEvaluator`
  - 类型匹配（CWE/类型双向包含）+ 定位误差（同文件行距归一化，0 精确 / 1 全错；
    阈值 0.5）→ TP/FP/FN。
  - **原始分母保持**：GT 有标签但无候选行 = FN（漏报），不算 invalid；
    unsupported/timeout/unavailable/invalid 单列进 excluded 并带原因，
    绝不删失败行后算准确率。
- `src/vulnagent/benchmark/adapters.py`
  - `ExploitGymDiscoveryAdapter.screen(...)`：四检查（本地可固定 / GT 可分离 /
    答案可隐藏 / 可安全沙箱）→ `eligible` / `not_blind` / `unsafe` + 原因。
  - `VulnGymCatalogBuilder.partition(...)`：按项目整块划分，禁止跨轨。
- `benchmarks/blind/`
  - `blind_catalog.yaml`：自研盲测清单（cp_parse 动态 CWE-121 held-out、
    py-cmd-001 CWE-78 dev、py-cmd-002 clean dev 反例）。
  - `ground_truth/`：评测侧标签目录，**Agent 运行时不可见**。
  - `exploitgym_candidates.yaml`：模拟筛选输入 + 筛选记录（真实选样需复查
    DATA_LICENSE，注明不随仓库再许可）。
- `experiments/run_blind_evaluation.py`：两轨实验器（A 筛选记录 / B 盲发现+评测）。

## 实测结果（本机，clang 23.1.2）

Track A（筛选记录）：
- `eligible`：eg-format-basic、eg-uaf-custom
- `case_study_only`：eg-heap-simple（答案可见）、eg-kernel-escape（不可沙箱/不可本地固定）

Track B（自研盲测，GT 全程隐藏，泄漏守卫 3/3 clean）：
```text
total_cases: 3    evaluable: 3    excluded: []
tp: 2    fp: 3    fn: 0
precision: 0.40    recall: 1.0    avg_loc_error: 0.1
```
- `cp_parse-vuln`：TP（crash → stack-buffer-overflow，loc_error 0.0）
- `py-cmd-001-vulnerable`：TP（loc_error 0.2）
- `py-cmd-002-clean`：**FP×3** —— Bandit 对 clean 样本的 subprocess 通用告警
  （B6xx 宽松规则）。这是真实 Precision 反例，按指导书要求保留在分母中，
  不删行、不隐藏；后续可用规则去重/置信度阈值降低 FP。

## 复现命令

```bash
python -m experiments.run_blind_evaluation
# 产物：artifacts/experiments/wp5-blind-eval/
#   screening.jsonl  leakage_guard.jsonl  candidates.jsonl  metrics.json  summary.json
```

## 测试

- `tests/unit/test_benchmark_screening.py`（6 项）：筛选判定（eligible/not_blind/
  unsafe+原因）、VulnGym 分区（同项目不跨轨）、泄漏守卫（干净/trigger+commit
  泄漏/知识重叠/GT 路径泄漏）。
- `tests/unit/test_blind_evaluator.py`（6 项）：TP/FP/FN 计数、原始分母保持
  （失败单列）、定位误差（错文件 → FN）、metrics.json 由评测器生成。
- `tests/integration/test_blind_eval_closed_loop.py`：泄漏守卫全 clean +
  筛选记录三类齐全 + 真实发现链路（静态三引擎 + 真实 libFuzzer）→ 评测闭环。
- 门禁：全量 `python -m pytest -q` 待合并前复跑。

## 有效性与边界（写入报告的有效性威胁节）

- 本盲测为**自定义协议**，绝非 ExploitGym 官方发现分数；VulnGym 官方数据
  需选样时复查许可后再行接入，当前清单为自研演示轨。
- clean 反例的 FP 来自 Bandit 通用 subprocess 规则，Precision 目前 0.40；
  这是真实误报测量，不是系统故障。
- 数据污染控制：固定模型版本、标签库在评测侧、Agent 环境无 GT 目录挂载。
