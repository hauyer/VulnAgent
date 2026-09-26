# VulnAgent 课程验收审计报告（再次检验）

> 审计日期：2026-09-25；审计基线：develop 工作树 + 提交 `ea2a0ba`/`92025e8`。
> 依据：《VulnAgent 漏洞挖掘实践：课程目标完整开发与验收指导书》（第 0/1/3/4/5/6/8/10 节）。
> 方法：逐项核对产物文件、运行门禁、重跑演练 runner、验证样本包；所有结论以磁盘上的可复现事实为准。

## 0. 本次审计执行的动作

| 动作 | 结果 |
|---|---|
| 全量 `python -m pytest -q` | **763 passed / 2 skipped**（基线 753 + 新增 10） |
| 前端 `tsc --noEmit` + `vite build` | 通过（本轮无前端改动，沿用上一轮实测） |
| 盲测端到端产物核对（`exploitgym-blind/`） | build/run/metrics/candidates/evidence/checksums 齐全，指标可复现 |
| 重跑 `run_zero_day_rehearsal` / `run_unknown_exploration` | summary 顶层 `state=draft`+`simulated_state`+SIMULATED 标注（修复遗留不一致，见 §6） |
| `samples/external_protection_v05/verify_static.ps1` | **15/15 OK**（哈希+格式全过） |

## 1. 四项照片要求 · 最终验收口径

| 照片要求 | 审计判定 | 事实依据 | 缺口 |
|---|---|---|---|
| ① 已知漏洞 PoC 与机理 | **部分满足**（1/2 动态复现） | QuickJS CVE-2023-48183 **真实动态复现**：漏洞版同 PoC 退出 0xC0000409（ASan 崩溃）、修复版退出 1 干净；案例卡含 call_chain/触发条件/修复 commit/PoC。GPAC CVE-2021-32132 与 libxml2 CVE-2022-23308 为 **static_only**（机理分析卡完整，`dynamic_run=false`，未做本地构建复现，也未给出充分 static_only 原因说明） | GPAC/libxml2 未动态复现或说明不足 |
| ② ExploitGym 多智能体挖掘 | **满足 1 条真任务盲测闭环**（协议诚实） | QuickJS nofuzz 任务固定双版本构建；盲态 runner 245 次模板输入执行、27 崩溃候选；独立评测 `tp=1 fp=0 fn=0`；GT 目录从不挂载 agent workspace；协议明示 `custom_discovery_not_official_score`。注册基线 18/18 单独标注、不计入发现指标 | 指导书"尽量 2–3 条不同项目"的扩展未做（非硬性） |
| ③ 未公开漏洞 | **未满足**（仅 L0 自研演练） | `benchmarks/unknown/` 3 个自研未知目标（fuzz-slot-table/fuzz-kv-store/unpublished-log-merge）真实 libFuzzer+ASan 崩溃已复现；探索档案与脱敏机制齐全 | 无**外部真实开源项目**（无预设阳性、授权）的探索与负结果记录（P1-C 未开工） |
| ④ 提交国家漏洞库 | **未满足但诚实标注** | 状态机诚信修复到位（P0-A）：演练恒 `draft`、`simulated_state` 单独承载、真实推进需人工回执；无任何"已联系/已提交"虚假状态。CNVD 提交模板与清单草稿已备 | 无真实平台回执（外部依赖，不承诺） |

## 2. 交付矩阵逐行核对

| 指导书验收口径 | 当前状态 | 判定 |
|---|---|---|
| ≥2 个真实已知漏洞完整案例（出处/修订/无害复现/修复对照/证据哈希） | 1 个（QuickJS）完整闭环；2 张卡 static_only | ⚠️ 部分 |
| ≥1 条真实 ExploitGym 任务固定为本地可研究目标、答案隔离、盲态候选、独立评测 | 1 条（QuickJS）全部达成 | ✅ 满足 |
| 外部未知目标探索一轮含负结果 | 无 | ❌ 未做 |
| 真实可披露发现经人工审核后由人提交并保存回执 | 无合格发现 → 交付脱敏草稿与未提交说明 | ✅ 诚实口径（未提交） |
| 旧 18/18 题卡登记不作为发现成绩 | 已从正式指标排除并单独标注 | ✅ |

## 3. 工作包退出条件

| 工作包 | 退出条件 | 状态 |
|---|---|---|
| P0-A 披露状态机 | 演练恒标模拟/未提交；无真实回执不可能显示已联系或已提交 | ✅ 完成（含本次审计修复的 summary 一致性） |
| P0-B 真任务重建 | ≥1 条真任务本地复原与烟测；可审计哈希；Agent 无答案 | ✅ 完成（QuickJS build+smoke：vuln crash/fixed clean） |
| P0-C 盲态 Agent 流程 | 候选由目标分析生成而非题卡；评测后才读 GT；失败样例入分母 | ✅ 完成（245 执行/27 候选/独立评测；GT 不可见测试） |
| P1-A 真实 CVE 复现 | ≥2 张真实卡有可验证原始证据或写明环境阻断 | ⚠️ 部分（1 张 reproduced；2 张 static_only 未解释） |
| P1-B 误报下降 | 持出样例定量减少 FP，不降低关键 TP | ❌ 未完成（`wp8-ablation` full+verification 臂 FP 仍 6，无下降） |
| P1-C 外部未知探索 | 真实外部目标至少一轮；负结果保留 | ❌ 未开工 |
| P2 披露与答辩包 | 有真实回执才称提交；结论可追溯到文件 | ⚠️ 部分（加壳样本包 15/15、CNVD 模板、盲测文档就绪；无回执） |

## 4. 测试清单 10 项逐项核对

| # | 指导书要求 | 对应测试 | 判定 |
|---|---|---|---|
| 1 | 未授权动态执行/路径逃逸/构建下载/未知二进制宿主运行拒绝 | `test_sandbox_policy`、`test_protected_sample_intake`、`test_controlled_executor` | ✅ |
| 2 | GT/补丁/PoC/CVE 特征不进 agent-visible；泄漏注入测试必须失败 | `test_exploitgym_blind.py::test_agent_workspace_never_contains_ground_truth`、`test_label_leakage_is_rejected` | ✅ |
| 3 | scanner 缺失/超时/报错与正常零发现四种结果，分母保留 | `test_runners.py`、`test_scanner.py`、`test_blind_evaluator.py` | ✅ |
| 4 | 题卡 CWE/patch file 不能成为正式盲挖候选来源 | `test_candidates_come_from_execution_not_case_card` + runner 签名无 GT | ✅ |
| 5 | shell=False/参数化 SQL/长度检查 clean 样例保持非确认 | bandit/source_audit 覆盖 shell=True 检出；**但 verification 侧 clean 不确认无定量测试，且 wp8-ablation 实测 FP=6 未减少** | ⚠️ 缺口 = P1-B |
| 6 | crash 可独立回放、与版本/输入哈希绑定；修复版对照；ASan 非零退出≠漏洞 | `test_real_libfuzzer_loop.py`、wp4 metrics（crash sha/replay/fixed clean/stack hash）、盲测 smoke 双版本对照 | ✅ |
| 7 | Discovery Agent 不能置 CONFIRMED；无 evidence 的 finding 被拒绝 | `test_verification_agent.py`、`test_evidence_verifier.py`、`test_independence.py` | ✅ |
| 8 | practice_mode/kind=none 不可推进；真实状态要有效回执；API 与 UI 同步 | `test_dossier_state_machine.py`、`test_dossier_api.py`、`test_unknown_exploration_loop.py` | ✅ |
| 9 | 未公开输入/敏感路径/完整堆栈不进公开视图 | dossier redact 测试 + 脱敏预览 API | ✅ |
| 10 | 全量 pytest + 前端 lint/build 合并前通过 | 763 passed / 2 skipped；tsc + vite build | ✅ |

## 5. 四层成果标记与诚实口径

| 层 | 现状 | 声明边界 |
|---|---|---|
| L0 自研教学演练 | 3 个未知目标 fuzz 崩溃、wp5 盲评（TP=2/FP=3）、wp8 消融（5 臂） | 可证明流程，不可证明现实新发现 |
| L1 真实已知漏洞复现 | QuickJS 1 条 reproduced；GPAC/libxml2 static_only | 证明 PoC/触发/验证能力，不称 0-day |
| L2 真实基准盲测 | 1 条真任务完整 run（tp=1/fp=0/fn=0，自定义协议） | 不冒充官方 exploit 评分 |
| L3 外部未知目标探索/披露 | 无外部项目探索；无提交回执 | 未达到 L3 门槛，如实标注 |

## 6. 本次审计发现并已修复的问题

- **遗留不一致（已修复）**：`wp8-zero-day` 与 `wp6-exploration` 的 summary 顶层仍为旧值 `state=maintainer_contacted`（仅 corrected 标注对冲），违反 P0-A"JSON 摘要状态一致"。重跑两个演练 runner 后：`state=draft`、`simulated_state=maintainer_contacted`、disclosure_note 含 SIMULATED 标注。原始 dossier 档案（原 + `_corrected` + `_correction`）全部保留，未覆盖历史证据。

## 7. 总体结论

**工程健康度与诚信闭环：达标。** 全部门禁绿（763 passed/2 skipped、前端 build 通过）；P0-A/P0-B/P0-C 完成；盲测协议诚实（自定义协议、GT 隔离、分母保留、候选来自执行）；加壳样本包 15/15；披露状态无虚假推进。

**四项照片要求完成度：①部分（1/2 动态复现）；②满足 1 条真任务盲测；③未满足；④未满足但诚实。** 与指导书"最大缺口是 ExploitGym 真目标的无泄漏盲挖"相比，该缺口已补上（1 条闭环）；剩余硬缺口为 **P1-B（误报抑制无定量改进）、P1-C（外部真实项目探索）、P1-A 补齐 1 张复现、以及第四项的外部回执（不可承诺）**。

**下一步建议（按优先级）**：P1-B 给 Verification 增加 guard/参数/数据流证据检查（`shell=False` 样例不确认、SQL 参数化、长度检查），在 `wp8-ablation` 同一样本上证明 FP 定量下降且 TP 不损失 → P1-C 选择一个本地可构建、许可允许、范围有限的外部开源项目（解析器/格式读取器）做一轮带负结果的探索 → P1-A 为 GPAC 或 libxml2 补本地构建复现或写明阻断原因 → P2 答辩包整合。
