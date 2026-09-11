# Benchmarks

当前提供四组明确授权、可复现的本地课程样本，以及两组严格闭源样本就绪台账：

- `manifest.json`：20 个 Python Source 样本，组成 10 个漏洞/安全配对家族，其中 8 个为导入别名、helper 传播、净化与近似调用 hard 样本；
- `binary/manifest.json`：14 个自研 C 样本，组成 7 个漏洞/安全配对家族，其中 8 个为 wrapper、变参或近似名称 hard 样本；分别编译为 Symbol-Rich 与 Stripped 两组，仅作静态检查；
- `elf/manifest.json`：6 个自研 C 样本，组成 3 个漏洞/安全配对家族，供 Linux/ELF 工具链编译为 Symbol-Rich、Stripped 与 PIE 三组；仅作静态检查；
- `fuzz/manifest.json`：1 个自研受控靶标，用 10 次配对试验比较引导式与随机变异。
- `packed/manifest.json`、`obfuscated/manifest.json`：各保留 2 个严格闭源软件槽位；只有来源、许可/授权、软件和保护器版本、SHA-256、格式、架构与预期事实齐全时才可变为 `materialized`。

Source/Binary 样本还记录 `family_id` 与 `difficulty`，用于验证每个家族同时具有漏洞和安全反例，并支持后续按难度分组。每个样本记录 `sample_id`、来源/许可证、语言、目标类型、Ground Truth、CWE、预期发现、授权边界和复现命令。生成的二进制、崩溃数据和实验结果写入 `artifacts/`，不作为源文件提交。

Binary 两组的唯一编译变量是是否传入 `-s`。当安全的 `snprintf` 与危险的 `sprintf` 在 MinGW CRT 中共享内部 helper 时，系统不会把 helper 名本身当作风险，而是对 PE x64 调用点做有界解码：只有第三参数寄存器出现无界长度哨兵才形成 `sprintf` 语义证据。新增 `vsprintf`/`vsnprintf`、真实 `sprintf` wrapper/自研 `sprintf_checked` 配对反例用于约束该策略；系统不会读取对应 `.c` 文件、文件名或 Ground Truth 来猜答案。

```bash
python -m experiments.run_source_ablation --manifest benchmarks/manifest.json --output-dir artifacts/experiments/source-ablation
python -m experiments.run_binary_benchmark --manifest benchmarks/binary/manifest.json --output-dir artifacts/experiments/binary-benchmark
python -m experiments.run_elf_benchmark --manifest benchmarks/elf/manifest.json --output-dir artifacts/experiments/elf-benchmark
python -m experiments.run_fuzz_ablation --manifest benchmarks/fuzz/manifest.json --output-dir artifacts/experiments/fuzz-ablation
python -m experiments.audit_protected_samples --manifest benchmarks/packed/manifest.json --manifest benchmarks/obfuscated/manifest.json --output-dir artifacts/experiments/protected-readiness
```

ELF runner 会先检查编译器 target，并在输出不是 `\x7fELF` 时失败；Windows MinGW 不能冒充 ELF 编译器。当前本机 WSL 损坏，因此真实 ELF 指标尚未生成。未知二进制、恶意样本和未授权目标不得进入默认执行流程。Source 与 Binary Benchmark 不执行被分析目标；Fuzz 仅执行清单内明确授权的本地教学靶标。Windows Fuzz 结果还记录 Job Object 资源控制及网络/文件系统隔离未实现的边界。

受保护样本 intake 只核验 manifest、路径边界、文件大小、magic 与 SHA-256，不执行目标，也不调用去壳或反编译工具。仓库当前四个槽位均为 `pending_user_supplied`，所以规范 readiness 必须显示 packing=0、obfuscation=0、`strict_requirement_met=false`。这不是功能失败，而是防止把占位、自研或无授权文件冒充课程要求的闭源软件。
