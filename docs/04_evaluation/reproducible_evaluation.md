# VulnAgent 可复现实验基线

## 实验边界

所有样本均为项目自研教学样本。Source 与 Binary 实验只读取代码或二进制，不执行目标；Fuzz 仅执行显式授权的本地靶标。Windows 运行使用 Job Object 强制活动进程数、Job CPU 时间、进程/Job 内存和 kill-on-close，并用 CPU accounting guard 处理宿主嵌套 Job 下的延迟终止；网络和文件系统隔离仍未强制，证据中明确标为 unsupported。非 Windows subprocess 后端只提供进程、墙钟超时和输出采集边界。结果目录为 `artifacts/experiments/`，每次运行都会记录清单哈希、Python 版本和生成时间。

## 2026-09-11 基线结果

| 实验 | 样本/试验 | Precision | Recall | F1 | 关键结果 |
|---|---:|---:|---:|---:|---|
| Verification OFF | 20 | 1.00 | 1.00 | 1.00 | 产生 10 个真实风险候选，但 Confirmed=0 |
| Verification ON | 20 | 1.00 | 1.00 | 1.00 | 相同发现输入上，10 个真实风险候选均被确认 |
| VulnAgent Source Full | 20 | 1.00 | 1.00 | 1.00 | 10 个配对家族与 8 个 hard 样本通过完整主链 |
| DeepSeek V4 Flash LLM Only | 20 | 1.00 | 1.00 | 1.00 | 真实 API；5,248 Token；weekday-peak 估算 0.002317218 USD；平均响应 2.938 秒 |
| GLM-5.2 LLM Only | 20 | 1.00 | 1.00 | 1.00 | 真实 API；5,803 Token；估算 0.069904 CNY；平均响应 3.700 秒 |
| Kimi K2.6 LLM Only | 20 | 1.00 | 1.00 | 1.00 | 真实 API；4,696 Token（缓存输入 3,088）；估算 0.0347383 CNY；含节流平均 13.884 秒 |
| Binary Symbol-Rich | 14 | 1.00 | 1.00 | 1.00 | 7/7 风险样本命中，7 个安全反例无误报 |
| Binary Stripped | 14 | 1.00 | 1.00 | 1.00 | 调用点语义恢复原 `sprintf` 漏报；7 个安全反例无误报 |
| Traditional Random Fuzz | 10 次 | 0.00 | 0.00 | 0.00 | 80 次执行未触达受控异常路径，覆盖代理均值 0.125 |
| Agent-Guided Fuzz | 10 次 | 1.00 | 1.00 | 1.00 | 同为 80 次执行，10/10 触达，覆盖代理均值 0.25 |

小样本下的点估计不代表充分统计置信度。Source Full 的 Precision/Recall 虽为 1.00，扩展后的 10 个阳性样本对应 Wilson 95% 下界约为 0.722，较原 6 个阳性的约 0.610 有所提高，但仍不能外推为真实世界检测率。

V0.4 Benchmark 第一阶段将 Source 从 12 扩展到 20、Binary 从 6 扩展到 10。新增 Source 使用导入别名、经过函数调用传播的 SQL、组合路径及同名安全 API 别名；新增 Binary 使用 `strcat`、`popen` 和 `strcpy_safely`、`systematic_report` 近似名称反例。Manifest 1.1 为全部 Source/Binary 样本记录 `family_id` 和 `difficulty`；实验行及运行清单同步保留这些字段。Part 2 又加入两组格式化函数对照，使 Binary 达到 14 个：`vsprintf` 对 `vsnprintf`，以及真实 `sprintf` wrapper 对自研 `sprintf_checked` 安全 wrapper。

真实三模型对比共完成 60 次分类调用，DeepSeek、GLM 与 Kimi 均为 20/20 请求成功，manifest SHA-256 与当前 20 样本 Source 清单一致。为了避免模型默认深度思考在 512-token 分类预算内耗尽输出，请求显式使用 `thinking={"type":"disabled"}`；DeepSeek/GLM 使用 `temperature=0`，Kimi K2.6 按官方接口约束由 Adapter 固定为 `temperature=0.6`，该差异进入 run manifest。三个 LLM-only 基线与其同次运行的 VulnAgent Full 分类结果相同，不能据此声称 VulnAgent 精度更高；可验证差异是 LLM-only 的 Evidence Chain Coverage 均为 0、Confirmed Findings 均为 0，而 VulnAgent Full 为 1.0 和 10。Adapter 直接解析供应商 usage：DeepSeek 共 4,340 prompt + 908 completion = 5,248 Token，GLM 共 4,629 + 1,174 = 5,803 Token，Kimi 共 3,677 + 1,019 = 4,696 Token，其中缓存输入 3,088。Cost 按 `run_manifest.json` 记录的 2026-09-11 官方费率估算，不同币种不相加，实际扣费以供应商账单为准。

Binary 实验对相同 14 个源码样本进行成对编译，唯一实验变量是是否使用 `-s` 去除符号。精确符号策略不会把 `snprintf`、`strcpy_safely`、`systematic_report`、`sprintf_checked` 或共享的 MinGW CRT helper `__stdio_common_vsprintf` 当作独立风险证据。对于 PE x64，该 helper 的 IAT/跳板调用点会由可选 Capstone 解码器进行有界局部分析：Windows x64 ABI 的第三参数寄存器 R8 只有在出现 `SIZE_MAX`（`-1`）哨兵时才推断为无界格式写入；动态长度仅记录为 bounded-count shape，不生成漏洞候选。该方法将原 Stripped Recall 0.800 提高到 1.000，并在新增 `vsnprintf` 与 `sprintf_checked` 反例下保持 FPR=0。它仍不证明路径可达、缓冲区大小或可利用性，非 PE x64 或未安装 Capstone 时明确降级为 unavailable。所有 Binary 风险候选仍由 Verification 标记为 `UNCERTAIN`，没有越权确认。

Fuzz 对比使用项目标记与解析器边界字符，不生成 shell 命令、SQL 语句或 Exploit。靶标专门对 `VULNAGENT_CODE_MARKER` 做受控异常响应，因此结果证明的是“静态假设可在固定预算下驱动动态探索”，不是对未知软件的漏洞发现率声明。10 次引导试验中的异常属于同一全局 Crash 指纹。2026-09-11 规范快照已在 Windows Job 后端重跑；`run_manifest.json` 保存 `sandbox_profiles`，显示 `kill_on_job_close`、活动进程数、Job CPU、进程内存和 Job 内存为 enforced，网络、文件系统和文件大小限制为 unsupported。资源限制造成的终止不会计为目标 Crash。

## 复现

```bash
python -m experiments.run_source_ablation --manifest benchmarks/manifest.json --output-dir artifacts/experiments/source-ablation
python -m experiments.run_binary_benchmark --manifest benchmarks/binary/manifest.json --output-dir artifacts/experiments/binary-benchmark
python -m experiments.run_elf_benchmark --manifest benchmarks/elf/manifest.json --output-dir artifacts/experiments/elf-benchmark
python -m experiments.run_fuzz_ablation --manifest benchmarks/fuzz/manifest.json --output-dir artifacts/experiments/fuzz-ablation --trials 10 --mutation-count 8
```

Binary 运行器会产生 14 个 Symbol-Rich 与 14 个 Stripped 分析行；两个 Profile 的二进制都只读取、不执行。重新运行后应以新生成的 `metrics.json` 为准；文档中的数值不是测试代码中的硬编码通过条件。

ELF runner 已用 Zig 0.16.0 的 `x86_64-linux-gnu` 交叉编译链完成 6 个样本、3 个配对家族、Symbol-Rich/Stripped/PIE 三 Profile 共 18 行真实实验。它验证 compiler target、ELF magic、分析器报告的 `file_format`，并记录 compiler version/machine、ELF type、架构和 SHA-256；所有目标只编译和读取，不执行。三个 Profile 均为 3 TP、0 FP、3 TN、0 FN，但每组只有 3 个正样本，Wilson 95% 下界约 0.438。

前端“本地安全测试实验室”提供独立 ELF-A 看板：总览直接展示 Fixture/Profile/Row 数量、编译器版本与目标执行边界，并逐 Profile 展示 TP/FP/TN/FN、Precision/Recall/F1 和 Evidence Chain Coverage。看板只读取 `artifacts/experiments/elf-benchmark/metrics.json` 与 `run_manifest.json`，产物缺失时明确显示未生成，不硬编码完成状态。

“验收矩阵”总览直接展示 LLM 对比的 P/R/F1、Token、分币种 Cost 和 Evidence Coverage；Provider 返回的 usage 或费率不存在时显示为不可用，不按零值处理。任务“审计报告”页通过只读导出接口提供自包含 HTML 与可打印 PDF，和 Markdown/JSON 操作位于同一入口。

由于 `artifacts/experiments/` 是运行时忽略目录，前端优先读取当前 `llm-comparison` 规范产物，缺失时只读回退到 `benchmarks/baselines/llm-comparison-v04.json` 中已发布的凭据安全聚合快照。界面会标明“已发布真实基线”及 manifest 匹配状态；该快照只用于展示，不参与当前 A 组验收状态计算。

## 真实多模型对比

DeepSeek、智谱 GLM 与 Kimi K2.6 的 HTTP Adapter、Planner 受约束 JSON 建议和多 Provider 对比脚本均已实现，并通过 `httpx.MockTransport` 契约测试。2026-09-11 三家均已完成当前 20 样本真实实验，共 60 次正式请求，全部返回 HTTP 200 和 usage；运行产物位于 `artifacts/experiments/llm-comparison/`，且不记录密钥或原始响应。Kimi Adapter 处理了 K2.6 固定温度约束，并通过 21 秒最小请求间隔与有界 429 退避遵守低 RPM 限制。

```bash
python -m experiments.run_llm_comparison --manifest benchmarks/manifest.json --providers deepseek glm kimi --output-dir artifacts/experiments/llm-comparison
```

该实验同时提供 Multi-Agent vs Single-LLM 与 Evidence Fusion vs LLM Only 的可执行对照。再次运行会产生真实 API 费用，结果必须从新生成的 `metrics.json` 引用。
