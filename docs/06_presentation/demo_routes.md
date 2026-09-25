# WP7 — 现场演示：三条固定路线（12–15 分钟）

对应开发指导书第 13 节。所有演示走真实 API 与真实工具证据；
页面状态区分"未运行 / 未确认 / 确认"，不夸大、不伪造。

## 前置条件（演示前 10 分钟检查）

```bash
# 后端
.\.venv\Scripts\python.exe -m uvicorn vulnagent.api.app:app --port 8000
# 前端（已构建到 dist/，由 FastAPI 直接挂载，无需单独起服务）
# 或开发模式： cd frontend && npm run dev   （Vite 代理 /api → :8000）

# 真实工具链（动态演示需要）
#  clang 23.1.2 已装于 C:\Program Files\LLVM（PATH 含其 bin）

# 门禁（可在演示中展示）
.\.venv\Scripts\python.exe -m pytest -q          # 750+ passed
cd frontend && npm run lint && npm run build      # tsc + vite build 通过
```

## 路线 1 — 主链闭环（4–5 分钟）

**目的**：证明一个真实多 Agent 任务从准入、事实、候选、独立复核到报告全链路可追溯。

1. UI 首页（Dashboard）新建任务：
   - 路径 `benchmarks/source/py-cmd-001-vulnerable/app.py`，类型 `source`
   - 点击「创建并运行」→ 状态徽章流转：等待 → 分析中 → 已完成
2. 打开任务详情：
   - **Trace**：展开事件时间线（task_started → source_analysis → … →
     verification → report），逐个展示 producer 与 payload
   - **候选**：CWE-78 命令注入候选（来源 agent、置信度、位置）
   - **证据**：源码位置、调用路径、工具输出
   - **复核**：CONFIRMED / REJECTED / UNCERTAIN 徽章（颜色区分）
   - **报告**：打开 HTML 报告，展示合规声明与证据链
3. 演示人工标注：在候选页点击「复核拒绝」，刷新后见标注记录。

**要点**：页面状态文案与颜色不可混淆——"未运行/未确认/确认"三态；
任何工具缺失都显示 `unavailable / not_run` 而不是 0 结果。

## 路线 2 — 真实动态缺陷（4–5 分钟）

**目的**：以真实工具证据复现授权动态缺陷，展示修复版对照与诚实状态。

1. 运行 WP4 真实闭环实验：
   ```bash
   python -m experiments.run_real_libfuzzer --runs 50000 --max-len 64 --seed 7
   ```
   打开 UI「实验」页 → `wp4-libfuzzer`：
   - `crashes=1`、`sanitizer_kind=stack-buffer-overflow`
   - `crash_input_sha256` / `stack_hash` / `replay_count=1`
   - **`fixed_outcome=clean`**（同一输入在修复版干净退出——修复对照）
2. 展开证据：CRASH_LOG 含崩溃输入哈希、Sanitizer 摘要、重放记录。
3. 诚实状态演示（可选）：临时把 `VULNAGENT_CLANG` 指向不存在路径重跑，
   引擎输出 `not_run + 原因`（工具链不可用 ≠ 0 findings）。

**要点**：崩溃、普通非零退出、超时、OOM 分开统计；不展示破坏性 payload，
只展示 Sanitizer/异常摘要与修复版同输入对照。

## 路线 3 — 研究探索（3–4 分钟）

**目的**：展示授权目标选择、一个被排除的误报和一个最有价值的候选。

1. UI「实验」页 → `wp5-blind-eval`：
   - 盲评指标：`tp=2 / fp=3 / fn=0 / precision=0.40 / recall=1.0`
   - 解释 **FP×3 是真实误报测量**（Bandit 对 clean 样本的通用 subprocess
     告警），按指导书保留在分母，不删失败行
   - 泄漏守卫 3/3 clean：标签全程在评测侧，Agent 环境无 GT 目录
2. UI「实验」页 → `wp6-exploration`：
   - 未知目标探索卷宗：`practice_mode=true`、"未提交"披露说明
   - 展示一个**被排除的候选**（duplicate_known：历史知识去重命中
     subprocess 已知问题）与**最有价值的候选**（cp_parse 崩溃 → 待人工复核，
     引擎不自行宣称新漏洞）
3. 三条演示路线总结板（可贴 docs/06_presentation/ 下的路线图）。

**要点**：不展示破坏性 payload；未公开发现只留哈希与摘要；卷宗明确
"Nothing has been submitted"。

## 可复现清单

| 演示内容 | 命令/入口 | 关键证据 |
|---|---|---|
| 主链闭环 | UI 任务页 + `/api/tasks/{id}/trace` | Trace、Findings、Evidence、Verification、报告 |
| 真实动态缺陷 | `python -m experiments.run_real_libfuzzer` | metrics.json：crash、sanitizer、replay、fixed_outcome |
| 盲评基准 | `python -m experiments.run_blind_evaluation` | metrics.json：TP/FP/FN、precision/recall、泄漏守卫 |
| 未知探索 | `python -m experiments.run_unknown_exploration` | dossier_redacted.yaml、triage.jsonl |
| 门禁 | `python -m pytest -q` + `npm run lint` + `npm run build` | 750+ pass / 2 skip；tsc、vite 通过 |

> 有效性威胁（演示时如被提问，如实说明）：盲测为自定义协议，非
> ExploitGym 官方分数；全部样本为自研教学 fixture；Precision 0.40 反映
> Bandit 通用规则误报，属于真实测量而非故障。
