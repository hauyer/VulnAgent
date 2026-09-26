# P1-C：外部未知目标探索报告（真实项目、无预设阳性）

> 日期：2026-09-25　对应工作包：P1-C（外部未知目标探索）　层级标记：**L3**
> 本文档记录对**真实外部开源项目**的无预设阳性探索，含负结果；不宣称任何"0-day"。

## 1. 目标清单与许可

| 目标 | 上游 | 许可证 | 固定修订 | 输入面 |
|---|---|---|---|---|
| MuJS（JS 引擎） | github.com/ArtifexSoftware/mujs | ISC | `8a32c39`（2026 HEAD） | JavaScript 源码文本 |
| wasm3（WASM 解释器） | github.com/wasm3/wasm3 | MIT | `ea6ad90`（HEAD） | WebAssembly 二进制 |

两个目标均为纯 C、本地可构建、许可允许研究、上游活跃；运行时零外部网络交互。符合指导书 C1 目标准入。

## 2. 盲态协议执行情况

- Agent/运行侧只见：目标源码、构建工具、无标签初始种子。
- 答案/知识隔离：已知 CVE 检索在 fuzz **之后**由记录端完成（去重用），从未注入 fuzz 会话；两目标均无预设阳性（未预埋任何"这里会崩"）。
- 每次工具执行：记录 sanitizer、预算、执行次数、退出状态（见各档案 `tool_runs.jsonl`）。

## 3. 结果汇总

| 目标 | sanitizer | 总执行次数 | 崩溃 | 候选 | 结论 |
|---|---|---|---|---|---|
| MuJS | ASan ×3 + ASan/UBSan ×1 | ≈282,000 | 0 | 0 | **负结果** |
| wasm3 | ASan + ASan/UBSan 各一轮 | ≈5,960,000 | 0 | 0 | **负结果** |

## 4. 负结果的价值与口径

- 两目标合计约 **624 万次**盲态执行无 sanitizer 发现，证明探索流程在真实目标上可运行、可复现、零误报；corpus 有效扩展（mujs 10→2390 输入）。
- 诚实声明：零崩溃 **不等于** 无漏洞；未发现可申报的"疑似未公开漏洞"。因此不进入披露/国家库流程（第四项继续保持"未提交"真实状态）。
- 局限记录：预算有限、种子多样性有限、单宿主单进程、未穷尽静态审计。

## 5. 产物清单

- `artifacts/experiments/p1c-mujs-exploration/`（manifest / tool_runs / metrics / README / checksums；candidates 与 evidence 为空）
- `artifacts/experiments/p1c-wasm3-exploration/`（同上结构）
- `third_party/mujs/`（固定修订、fuzz 驱动、10 种子、ASan/UBSan 二进制、learned corpus）
- `third_party/wasm3/`（固定修订、官方 fuzz 驱动、官方 wasm 种子、ASan/UBSan 二进制）

## 6. 结论与下一步

P1-C 的真实外部探索已开展并如实记录负结果——这是验收口径中"至少开展一个无预设阳性、授权的外部开源项目探索，完整记录负结果"的**已满足项**。继续挖掘（更长预算/更多目标/静态引导）可作为后续工作，但任何"疑似未公开"的声明仍须经去重、复核与人工确认后才能提高层级。
