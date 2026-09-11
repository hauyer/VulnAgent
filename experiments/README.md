# Experiments

实验运行器输出 `labelled_results.json`、`metrics.json`、`metrics.csv` 和带输入 SHA-256 的 `run_manifest.json`。分类指标包含 Wilson 95% 区间；运行指标包含时间、Agent 步数、证据链覆盖率、Token usage/估算 Cost、覆盖代理、Crash 数和跨试验去重后的 Crash 签名数。Fuzz 行与运行清单还保存 `sandbox_profiles`，区分 enforced 与 unsupported 控制。供应商未返回 usage 或未配置费率时保持 `null`，不会伪造为零。

当前可直接复现：

```bash
python -m experiments.run_source_ablation --manifest benchmarks/manifest.json --output-dir artifacts/experiments/source-ablation
python -m experiments.run_binary_benchmark --manifest benchmarks/binary/manifest.json --output-dir artifacts/experiments/binary-benchmark
python -m experiments.run_elf_benchmark --manifest benchmarks/elf/manifest.json --output-dir artifacts/experiments/elf-benchmark
python -m experiments.run_fuzz_ablation --manifest benchmarks/fuzz/manifest.json --output-dir artifacts/experiments/fuzz-ablation --trials 10 --mutation-count 8
python -m experiments.audit_protected_samples --manifest benchmarks/packed/manifest.json --manifest benchmarks/obfuscated/manifest.json --output-dir artifacts/experiments/protected-readiness
```

配置 `DEEPSEEK_API_KEY`、`GLM_API_KEY` 与 `KIMI_API_KEY` 后，可运行会产生真实 API 调用和费用的三模型对比：

```bash
python -m experiments.run_llm_comparison --manifest benchmarks/manifest.json --providers deepseek glm kimi --output-dir artifacts/experiments/llm-comparison
```

该脚本显式关闭模型的深度思考模式，使短 JSON 分类预算尽量一致；Kimi K2.6 由 Adapter 按官方约束固定为 `temperature=0.6`，并通过 21 秒最小间隔及有界 429 退避适配低 RPM 账户。脚本保存解析后的公开结论、原始响应 SHA-256、供应商 usage 和版本化费率估算，不保存密钥、原始响应或私有推理，也不把模型自然语言当作证据。无密钥时应明确失败，禁止生成占位成绩。2026-09-11 的当前 manifest 真实运行已完成 60 次成功请求，产物位于 `artifacts/experiments/llm-comparison/`。

三组实验分别回答：

- 相同发现输入下 Verification ON/OFF 的 Verdict 差异，以及完整运行时是否保持一致；
- Binary Reverse、Logic、Obfuscation、Verification 是否能通过统一运行时形成证据链，以及保留/去除编译符号如何改变可观测性、误报与漏报；
- 在完全相同的执行预算下，静态风险引导能否提高受控路径触达率和覆盖代理。
- 两个或更多 Single-LLM 基线与 Evidence-First Full 在 Precision、Recall、证据覆盖、耗时、Token 和 Cost 上的差异。

2026-09-11 的本机基线结果见 `docs/04_evaluation/reproducible_evaluation.md`。V0.4 已扩展到 20 个 Source 与 14 个 Binary 样本，并将 `family_id`/`difficulty` 写入 labelled rows 和 run manifest；Binary labelled rows 还记录调用点语义来源与数量。DeepSeek/GLM/Kimi 已在当前 20 样本 manifest 上重跑并记录真实 usage。这些结果只能证明机制可行，不能外推为真实世界漏洞检测能力。

Windows 上的 Fuzz 规范快照使用 Job Object 资源后端：活动进程数、Job CPU、进程/Job 内存和关闭回收已强制；网络、文件系统和文件大小限制仍明确为 unsupported。该后端不是虚拟机，也不能用于未知或未授权程序。

`audit_protected_samples` 是闭源加壳/混淆材料的只读准入门禁，不是检测成绩 runner。它要求每类至少 2 个不同软件均通过来源、条款/授权、哈希、格式和路径校验后才把 `strict_requirement_met` 设为 true；`--require-complete` 可在材料未齐时用退出码 2 阻止验收流水线继续。

ELF runner 要求 Linux/WSL 或显式 ELF cross-compiler，固定生成 Symbol-Rich、Stripped 与 PIE 三个 Profile，并在分析前验证 ELF magic。当前已使用固定版本 Zig 0.16.0 的 `x86_64-linux-gnu` 目标完成 6 个 Fixture × 3 Profile = 18 行真实 ELF 静态实验；规范结果位于 `artifacts/experiments/elf-benchmark/`，目标执行次数为 0。
