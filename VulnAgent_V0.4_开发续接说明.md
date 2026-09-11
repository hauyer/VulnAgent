# VulnAgent V0.4 开发续接说明

> 最后更新：2026-09-11  
> 当前开发主线：高级功能与可验证实验增强  
> 使用方式：新对话开始前先阅读本文件、`AGENTS.md` 和 `VulnAgent_V0.4_高级功能开发规划.md`。

> 课程三组测试对象的严格验收缺口、后续修复顺序及完成判据，见 `VulnAgent_V0.4_课程测试要求验收缺口与后续开发.md`。该文档按“发现 + 独立复核 + Evidence + 受控利用验证”口径评估，优先于仅按样本接入数量判断完成度。

## 1. 当前结论

V0.4 Part 1“Benchmark 扩展第一阶段”、Part 2“Stripped 二进制召回改进”、Part 3“真实 ELF Benchmark/Demo”、Part 4“报告与一键演示增强”、Part 5“Windows Job Object 资源沙箱”、Part 6A“加壳/混淆样本准入门禁”、Part 6B“4 个授权教育逆向样本静态实测”、Part 7“HTML/PDF 报告导出与一键演示”、Part 8“LLM Usage/Token/Cost”、Part 9“前端演示与本地样本导入加固”及优先级矩阵第 10 项“Kimi 第三 Provider 真实实测”均已完成。

本轮没有修改冻结的 `Task`、`AgentMessage`、`VulnerabilityCandidate`、`Evidence` 公共协议，也没有改变“只有 Verification 层可以写入 `CONFIRMED`/`REJECTED`”的边界。

## 2. Part 1：Benchmark 扩展第一阶段（已完成）

### 2.1 Source Benchmark

`benchmarks/manifest.json` 已升级到 schema 1.1，共 20 个样本：

- 10 个漏洞样本、10 个安全反例；
- 10 组按 `family_id` 配对的漏洞/安全样本；
- 12 个 basic、8 个 hard；
- 新增跨函数、别名、环境变量、近似安全 API 和 sanitizer 等更接近真实代码的场景；
- 新增目录：`py-cmd-003/004`、`py-sql-003/004`、`py-path-003/004`、`py-eval-003/004`。

扩展后的 Source 消融结果：

| Arm | 样本 | Precision | Recall | F1 | Confirmed | Evidence Coverage |
|---|---:|---:|---:|---:|---:|---:|
| Baseline | 20 | 1.000 | 1.000 | 1.000 | 0 | 1.000 |
| Verification ON | 20 | 1.000 | 1.000 | 1.000 | 10 | 1.000 |
| Full | 20 | 1.000 | 1.000 | 1.000 | 10 | 1.000 |

10 个阳性样本下 Precision/Recall 的 Wilson 95% 下界约为 0.722。该结果证明课程样例上的机制闭环，不代表真实世界检测率。

### 2.2 Binary Benchmark

`benchmarks/binary/manifest.json` 已升级到 schema 1.1，共 10 个样本：

- 5 个漏洞样本、5 个安全反例；
- 5 组 `family_id` 配对样本；
- 6 个 basic、4 个 hard；
- 新增 `strcat`、`popen` 风险样例；
- 新增 `strcpy_safely`、`systematic_report` 近似名称安全反例；
- 所有目标仅编译和静态分析，实验记录中 `target_executed=false`。

扩展后的 Binary 结果：

| Profile | 样本 | Precision | Recall | F1 | FPR | 当前漏报 |
|---|---:|---:|---:|---:|---:|---|
| Symbol-Rich | 10 | 1.000 | 1.000 | 1.000 | 0.000 | 无 |
| Stripped | 10 | 1.000 | 0.800 | 0.889 | 0.000 | `sprintf` 风险样例 |

安全的 `snprintf`、`strcpy_safely` 和 `systematic_report` 均未被误报。Stripped 组唯一漏报已作为 Part 2 的目标，不允许使用文件名、目录名、Ground Truth 或样例专用字符串修补。

### 2.3 实验框架改动

以下 runner 的 labelled rows 与 run manifest 已传播 `family_id`、`difficulty`，并记录 family/difficulty 统计：

- `experiments/run_source_ablation.py`
- `experiments/run_binary_benchmark.py`
- `experiments/run_llm_comparison.py`

主要产物：

- `artifacts/experiments/source-ablation/`
- `artifacts/experiments/binary-benchmark/`

2026-09-11 已在扩展后的当前 20 样本 manifest 上重跑 DeepSeek、GLM 与 Kimi，各 20 次、共 60 次请求均成功并返回 usage；规范产物位于 `artifacts/experiments/llm-comparison/`。

### 2.4 验证结果

- `python -m pytest`：396 passed，1 个来自 Starlette/AnyIO 的第三方弃用警告；
- 前端 `npm run lint`：通过；
- 前端 `npm run build`：通过；
- Source/Binary 清单路径、配对关系和难度统计：通过；
- 26 个文本实验产物的 API Key/Token/Secret 字面值扫描：0 命中；
- Binary Benchmark 目标执行标志：均为 false。

复现命令：

```powershell
.\.venv\Scripts\python.exe -m experiments.run_source_ablation --manifest benchmarks\manifest.json --output-dir artifacts\experiments\source-ablation
.\.venv\Scripts\python.exe -m experiments.run_binary_benchmark --manifest benchmarks\binary\manifest.json --output-dir artifacts\experiments\binary-benchmark
.\.venv\Scripts\python.exe -m pytest -q --basetemp .pytest-v04-benchmark-full
```

## 3. Part 2：Stripped 二进制召回改进（已完成）

### 3.1 实现

- PE 解析结果的私有 `format_details.import_entries` 现在记录 IAT RVA/地址，没有修改公共 Binary Contract；
- 新增 `src/vulnagent/analyzers/binary/reverse/_callsite.py`；
- 对 PE x64 可执行区段做有界 Capstone 解码，定位 `__stdio_common_vsprintf` 的 IAT、跳板和调用点；
- 根据 Windows x64 ABI 跟踪第三参数寄存器 R8：只有 `SIZE_MAX`/`-1` 哨兵才产生 `unbounded_format_write`；动态长度只记录 `bounded_count_shape`；
- 确认前生成的是 `DISASSEMBLY` Evidence 与 `UNCERTAIN` 候选，不证明路径可达、目标缓冲区大小或可利用性；
- 未安装 Capstone、非 PE x64、超过字节/指令上限时均显式降级，不猜测结果；
- Binary runner 记录 `signal_bases`、`semantic_callsite_count` 和 Capstone 版本。

实现不读取 `.c` 源码、样本 ID、文件名、目录名或 Ground Truth。

### 3.2 新增配对反例

Binary manifest 从 Part 1 的 10 个进一步扩展到 14 个：

- 7 个漏洞样本、7 个安全反例；
- 7 个配对家族；
- 6 个 basic、8 个 hard；
- `case-011`/`case-012`：`vsprintf` 与 `vsnprintf` 变参对照；
- `case-013`/`case-014`：真实 `sprintf` 函数指针 wrapper 与自研 `sprintf_checked` 安全近似名对照。

### 3.3 最终实验结果

| Profile | 样本 | TP | FP | TN | FN | Precision | Recall | F1 | FPR |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Symbol-Rich | 14 | 7 | 0 | 7 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| Stripped | 14 | 7 | 0 | 7 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |

相比 Part 1，Stripped Recall 从 0.800 提升到 1.000，F1 从 0.889 提升到 1.000。三类无界格式写入样本在两个 Profile 中均带调用点语义；`snprintf`、`vsnprintf`、`sprintf_checked` 及其他安全近似名样本保持零误报。28 个分析行 `target_executed=false`，全部 Evidence Chain Coverage=1.0，Binary 候选仍全部为 `UNCERTAIN`。

当前精度只针对 7 个自研阳性与 7 个安全反例，Precision/Recall 的 Wilson 95% 下界约 0.646，不可外推成真实世界 100%。

### 3.4 测试与产物

- 相关 Binary/Experiment/Benchmark 测试：65 passed；
- 规范产物已更新：`artifacts/experiments/binary-benchmark/`；
- run manifest：14 fixtures、7 families、28 rows、Capstone 5.0.9、目标未执行；
- 全量 Python：402 passed，1 个来自 Starlette/AnyIO 的第三方弃用警告；
- 前端 `npm run lint` 与 `npm run build`：通过。

## 4. Part 3：真实 ELF Benchmark/Demo（ELF-A 已完成）

### 4.1 已完成

- 新增 `benchmarks/elf/manifest.json`：6 个自研 C 样本、3 个漏洞/安全配对家族；
- 新增 `experiments/run_elf_benchmark.py`；
- 固定 Symbol-Rich（non-PIE）、Stripped（non-PIE）、PIE 三 Profile；
- 编译后先校验 `\x7fELF` magic，再进入 Binary Agent 主链；
- runner 记录 compiler、version、target machine、host、ELF type、架构、SHA-256；
- 全程只编译和静态读取，`target_executed=false`；
- 新增 manifest 配对、Profile flags、错误格式拒绝和 Windows target 拒绝测试；
- ELF 相关目标测试：73 passed。

### 4.2 环境检查与解决方案

- 初始环境没有可用的 Linux 编译器；
- 本机 GCC target：`x86_64-w64-mingw32`，runner 会在写实验结果前明确拒绝；
- WSL2 Ubuntu 已注册但启动失败：`WSL_E_DISK_CORRUPTED`；
- 没有注销、重装、删除或修复 WSL；
- 已下载并校验官方 Zig 0.16.0 Windows x64 发行包，runner 显式使用 `zig cc -target x86_64-linux-gnu`；
- Zig 存放于 Git 忽略的 `tools/zig/`，编译器版本、命令前缀和 target triple 均写入 `run_manifest.json`。

### 4.3 真实实验结果

规范产物：`artifacts/experiments/elf-benchmark/`，其中 `summary.md` 可直接用于答辩。

| Profile | 样本 | TP/FP/TN/FN | Precision | Recall | F1 | Evidence Coverage |
|---|---:|---|---:|---:|---:|---:|
| Symbol-Rich ET_EXEC | 6 | 3/0/3/0 | 1.0 | 1.0 | 1.0 | 1.0 |
| Stripped ET_EXEC | 6 | 3/0/3/0 | 1.0 | 1.0 | 1.0 | 1.0 |
| PIE/ET_DYN | 6 | 3/0/3/0 | 1.0 | 1.0 | 1.0 | 1.0 |

共 6 个自研授权 Fixture、3 个漏洞/安全配对家族、18 条真实 ELF 分析记录；`target_execution=false`。每个 Profile 只有 3 个正样本，Precision/Recall 的 95% Wilson 下界约 0.438，因此不能把 F1=1.0 宣传为真实世界 100% 检出率。所有 Finding 仍为 `UNCERTAIN`，没有绕过 Verification-only confirmation。

复现命令：

```powershell
.\.venv\Scripts\python.exe -m experiments.run_elf_benchmark --manifest benchmarks\elf\manifest.json --output-dir artifacts\experiments\elf-benchmark --compiler tools\zig\zig-x86_64-windows-0.16.0\zig.exe
```

## 5. Part 4：报告与一键演示增强（已完成）

### 5.1 实现

- `scripts/demo_source_v03.py` 现在可选写出完整 JSON 报告，同时保持原无参数入口兼容；
- 新增 `scripts/demo_v04.py`，一条命令运行 Source、Binary 和授权 Fuzz 三条主链；
- 生成 `artifacts/demos/v04/source.json`、`binary.json`、`fuzz.json`、`index.json` 与 `summary.md`；
- 只读取已有 LLM 指标，不发起任何外部模型调用；
- 自动对 manifest SHA-256；当前 20 样本 LLM 快照标为 `current`，旧批次仍会标为 `frozen_prior_scope`；
- 真实 ELF 快照依据 manifest SHA-256 标为 `current` 或 `stale`；
- 非付费实验 manifest 不匹配时标为 `stale`，防止不同批次指标被混用；
- 写 bundle 前拒绝 API Key/Token/Secret 形字段；文件使用临时文件替换写入；
- 提供 `--skip-fuzz` 只读演示模式。

### 5.2 已验证现场结果

2026-09-11 本机一键运行成功：

| 主链 | 状态 | Findings | Confirmed | 目标执行 |
|---|---|---:|---:|---|
| Source | completed | 4 | 4 | false |
| Binary | completed | 1 | 0 | false |
| Fuzz | completed | 2 | 2 | true（仅自研授权靶标） |

快照索引状态：Source/Binary/Fuzz/ELF/LLM=`current`；Part 6B 受保护样本实验也单独校验两个 manifest 哈希。`external_llm_calls_started=false`，即生成演示包不会再次计费。

复现：

```powershell
.\.venv\Scripts\python.exe scripts\demo_v04.py --output-dir artifacts\demos\v04
```

## 6. Part 5：Windows Job Object 资源沙箱（已完成）

### 6.1 实现

- 完成 `src/vulnagent/sandbox/backends/windows_job.py`，Windows 默认由 `SandboxManager` 选择该后端；
- Job 在目标启动前创建并设置 `kill_on_job_close`、活动进程数、Job CPU、进程内存和 Job 内存限制；
- 目标以 suspended 状态创建，成功挂入 Job 并经 `IsProcessInJob` 验证后才恢复；任何设置、创建或挂入失败均 fail closed，不静默回退到 subprocess；
- 使用 Job accounting guard 按聚合内核/用户 CPU 时间补充终止，解决宿主嵌套 Job/打包解释器环境中 Job time 自动终止通知可能延迟的问题；
- `.py` 靶标在 Windows 上解析到真实安装解释器，避免虚拟环境或 Microsoft Store launcher 派生出未直接纳管的解释器；
- 超时和 CPU 限制均终止整个 Job；资源限制造成的终止不会被标为目标 Crash，也不会生成伪 `CRASH_LOG`；
- `SandboxResult.metadata`、Fuzz `RUNTIME_TRACE`/`TOOL_RESULT` Evidence 和 Fuzz 汇总均记录 backend、内核限制、accounting、enforced/unsupported controls；
- subprocess 后端同样显式记录自身能力，不再只保存容易误解的策略布尔值。

### 6.2 实际验证

无害自研测试已验证：

- 正常目标在 Job 中运行并记录内核限制；
- `max_processes=1` 时子进程创建被拒绝；
- 100ms CPU 忙循环连续 5 次均在约 0.3 秒内由资源边界终止，而不是等到 5 秒墙钟超时；
- 64MB 内存策略阻止 256MB 分配；
- Windows 默认后端确为 `WindowsJobBackend`；
- 资源终止与真实异常退出分类分离。

Part 5 完整门禁：

- 沙箱/Fuzz 相关测试：40 passed；
- 全量 Python：417 passed，1 个 Starlette/AnyIO 第三方弃用警告；
- 前端 `npm run lint`：通过；
- 前端 `npm run build`：通过。

### 6.3 重跑实验与现场包

规范 Fuzz 消融实验已在 Windows Job 后端重跑，`artifacts/experiments/fuzz-ablation/run_manifest.json` 保存真实 `sandbox_profiles`：

- enforced：`kill_on_job_close`、`active_process_limit`、`job_cpu_time_limit`、`process_memory_limit`、`job_memory_limit`；
- resource limits：4 processes、1000ms CPU、256MB memory；
- unsupported：file size、filesystem isolation、network isolation；
- fail closed：true。

结果保持：Guided 10/10 触达、Random 0/10，两个方法每轮同为 8 次执行；Guided/Random 覆盖代理均值分别为 0.25/0.125。`scripts/demo_v04.py` 已再次运行，现场 Fuzz JSON 同步显示 Windows Job profile，且没有发起外部 LLM 调用。

### 6.4 仍然存在的边界

- Job Object 不能提供网络隔离或文件系统白名单/只读挂载；
- `max_file_size_mb` 尚未由操作系统强制；
- 非 Windows 平台仍使用能力较弱的 subprocess 后端；
- 因此本 Part 只称为“资源和进程树沙箱”，不能宣传成虚拟机或完整隔离 Worker；
- 未知、第三方或未授权程序仍禁止执行。完整网络/文件系统隔离属于未来 Sandbox-B，不能通过修改宿主机全局防火墙来伪造。

## 7. 未启动的后续队列

矩阵第 2、4 项已经完成；以下项目仍只保留规划：

1. 在隔离 Worker 条件成熟后单独实现 Sandbox-B 网络/文件系统隔离；
2. ELF-B 的 `PT_DYNAMIC`/重定位恢复与 ELF-C 的更强反汇编；
3. 三模型对比专页、EXE/安装包交付和 PPTX 制作。

后续只有在用户明确继续时才启动；每完成一个 Part，都必须同步更新本文件，写明实现、实验、回归、已知限制和下一步。

## 8. Part 6A：加壳/混淆闭源样本准入门禁（已完成）

### 8.1 实现

- 新增 `benchmarks/packed/manifest.json` 与 `benchmarks/obfuscated/manifest.json`，每类 2 个受保护二进制样本槽位；
- 每个 `materialized` 样本必须记录不同软件身份与版本、闭源属性、保护器及版本、来源 URI、条款/授权说明、静态分析授权、SHA-256、PE/ELF 格式、架构和预期事实；
- 槽位从 `pending_user_supplied` 演进为经来源、条款与哈希核验的 `materialized`，动态执行仍固定为 false；
- 新增 `experiments/audit_protected_samples.py`，只读验证 manifest、路径必须位于各自 `materials/`、文件大小、magic 与 SHA-256；
- 样本路径逃逸、哈希变化、格式不符、缺少来源或静态分析授权均会拒绝；
- 只有 packing 与 obfuscation 各至少 2 个不同软件通过门禁，`strict_requirement_met` 才为 true；
- `--require-complete` 在材料不齐时返回退出码 2，避免自动化流程误把待办当完成；
- 二进制材料目录加入 `.gitignore`，防止样本误进 Git；手工压缩交付时仍需按课程内部提交范围处理；
- 一键演示摘要新增严格就绪表，并比较 readiness 中的两个 manifest 哈希。

### 8.2 当前真实结果

规范产物：`artifacts/experiments/protected-readiness/readiness.json`。

| 类别 | 要求软件数 | 当前就绪 | 状态 |
|---|---:|---:|---|
| Packing | 2 | 2 | materialized |
| Obfuscation | 2 | 2 | materialized |

`strict_requirement_met=true`、`target_execution=false`。四个文件均通过来源、授权声明、不同程序身份、PE magic、文件大小和 SHA-256 门禁。

### 8.3 验证与下一步条件

- Part 6A 新增测试：5 passed；
- 与一键演示集成的相关测试：9 passed；
- 测试覆盖四个完整不同软件时门禁为 true、缺授权拒绝、哈希不符拒绝、路径逃逸拒绝和全程不执行目标。

### 8.4 Part 6B：四样本静态实测（已完成）

选择的都是作者为逆向分析而制作、由 crackmes.one 明确允许非商业课程使用并要求署名的教育挑战，不是恶意软件，也没有执行：

| 类别 | 样本 / 作者 | 保护方式 | SHA-256 前缀 |
|---|---|---|---|
| Packing | aj21h's Spaghetti / aj21h | UPX + 自定义 VM | `f80f946a259c` |
| Packing | Custom packed crackme / Kowfsun | 自定义 C-stub packer + 字节码 VM | `99279210c3eb` |
| Obfuscation | MCM 2.0 / CrackNotMe | 指令虚拟化、数学与多进程保护 | `553996fbd290` |
| Obfuscation | C# .NET Extended Obfuscation / Desync | JIT-on-demand、IL 恢复与字符串混淆 | `f6469b1c98d9` |

新增 `experiments/run_protected_benchmark.py`，在严格准入后依次执行内置二进制分析、Obfuscation Analyzer、radare2 静态函数/CFG/伪代码、UPX 只读检查、经 manifest 授权的文件级解包、正式 Orchestrator、Evidence、Verification 与 Report 主链。`scripts/demo_v04.py` 已把该批次作为独立、带 manifest 哈希的快照接入一键摘要。

真实结果：严格准入 2+2；静态信号 4/4；正式主链 4/4；Evidence 链完整 4/4；radare2 伪代码 3/4；UPX 文件变换成功 1 个；目标执行 0 次。两个混淆样本产生 Finding 且保持 `UNCERTAIN`。每个样本均生成 JSON/HTML/PDF。

规范入口：`artifacts/experiments/protected-benchmark/summary.md`。四个挑战没有漏洞 Ground Truth，因此这批实验不计算漏洞 Precision/Recall，不把 Crackme 口令求解或文件解包冒充漏洞利用成功。这一限制必须在答辩中主动说明。

## 9. Part 7：HTML/PDF 报告导出与一键演示（已完成）

### 9.1 实现

- 新增 `src/vulnagent/report/html.py`，把现有结构化 `ReportResult.content` 投影为可离线打开的自包含 HTML，不引入第二套漏洞 Schema；
- HTML 包含任务与风险摘要、Finding、Evidence、独立复核、修复建议、时间线和已知限制，所有不可信文本均转义；
- HTML 使用严格 CSP，不包含脚本和外部资源，写出过程采用临时文件原子替换；
- 新增 `src/vulnagent/report/pdf.py`，通过可选依赖 ReportLab 生成结构化 PDF，使用 CID 中文字体，包含分页页脚、Finding、Verification、Remediation、Evidence 和 Timeline；
- PDF 同样只读取既有报告内容，使用临时文件原子替换；缺少可选依赖时明确报错，不伪造 PDF；
- 新增 `scripts/export_report_html.py` 与 `scripts/export_report_pdf.py` 两个独立导出入口；
- `scripts/demo_v04.py` 默认一次生成 Source/Binary/Fuzz 三组 JSON、HTML 和 PDF，`index.json` 记录全部产物，`summary.md` 提供离线报告链接；
- 增加 `--skip-pdf`，允许没有 ReportLab 时保留 JSON/HTML 演示路径；安装入口为 `python -m pip install -e ".[test,binary-analysis,report-export]"`。

### 9.2 真实产物与验证

规范目录 `artifacts/demos/v04/` 当前包含：

- `source.html` / `source.pdf`：4 个 Finding、20 条 Evidence、4 个独立复核结果，PDF 6 页；
- `binary.html` / `binary.pdf`：1 个 Finding，PDF 2 页；
- `fuzz.html` / `fuzz.pdf`：2 个 Finding，PDF 4 页；
- 对应的三个 JSON、`index.json` 与 `summary.md`。

验证结果：

- Playwright 在最终静态服务器中实测 Source HTML：完整展示 Finding、Evidence、Verification 和修复建议，控制台 0 error / 0 warning；
- 恶意样式文本转义测试通过，报告未执行脚本、未加载外部资源；
- 使用 `pypdf` 验证三个 PDF 页数与可解析性，并使用 `pypdfium2` 渲染 Source PDF 首页完成人工目视检查；
- 本轮最终全量 Python：442 passed，1 个 Starlette/AnyIO 第三方弃用警告；
- 前端 `npm run lint` 与 `npm run build`：通过；
- 排除本地 `.env` 后的凭据字面值与凭据赋值扫描：均为 0 命中；
- 没有修改冻结公共协议，没有发起外部 LLM 调用。

### 9.3 后续集成

随后按用户明确要求完成 Part 6B、真实 ELF-A 和 Part 9 演示界面加固，并把相关结果接入一键演示摘要；Sandbox-B、三模型对比专页、EXE 打包和 PPTX 仍未启动。

## 10. Part 8：LLM Usage / Token / Cost（已完成）

### 10.1 实现

- 在不破坏 `BaseLLM.generate -> str` 的前提下新增 `generate_with_usage -> LLMResponse`；
- `LLMUsage` 只保存 prompt、completion、total、cached prompt Token 和可选估算费用，不保存私有推理；
- OpenAI-compatible Adapter 兼容 `prompt_tokens`/`completion_tokens` 与 `input_tokens`/`output_tokens`，并解析 DeepSeek cache hit、Kimi `cached_tokens` 等常见缓存字段；
- `LLMPricing` 按未缓存输入、缓存命中输入、输出三种每百万 Token 费率估算，费率日期、来源、币种和“estimate”标记进入 `run_manifest.json`；
- `run_metrics.py` 新增各方法的 usage 可用请求数、Token 总计、费用总计/均值和币种；不同币种不相加；
- 新增 `artifacts/experiments/llm-comparison/summary.md`，可直接用于 PPT/答辩。

### 10.2 真实结果

| 方法 | 请求 | Prompt | Completion | Total | 估算费用 | Evidence Coverage |
|---|---:|---:|---:|---:|---:|---:|
| DeepSeek V4 Flash | 20/20 | 4,340 | 908 | 5,248 | 0.002317218 USD（weekday peak） | 0.0 |
| GLM-5.2 | 20/20 | 4,629 | 1,174 | 5,803 | 0.069904 CNY | 0.0 |
| Kimi K2.6 | 20/20 | 3,677 | 1,019 | 4,696 | 0.0347383 CNY | 0.0 |
| VulnAgent Full | 20 | — | — | — | — | 1.0 |

三家 LLM-only 与 Full 在该教学集上均为 10 TP、0 FP、10 TN、0 FN；不能据此声称 VulnAgent 分类精度更高。可验证差异是 LLM-only 没有 Evidence/独立确认，而 Full 具有完整 Evidence Coverage。Kimi 返回 3,088 个缓存输入 Token；费用只是按 2026-09-11 运行时记录费率计算的估算，最终扣费以各供应商账单为准。

### 10.3 Kimi 第三 Provider（已完成真实实测）

- 新增 `KimiAdapter`，默认官方 `https://api.moonshot.cn/v1` 与 `kimi-k2.6`；
- Kimi 使用官方建议的 `max_completion_tokens`，支持 JSON Mode 与关闭 K2.6 thinking，并在 Adapter 内固定该模型唯一接受的 `temperature=0.6`；
- Settings、`.env.example`、Router 缺 Key 明确失败、Planner 注入和三 Provider runner 均已接通；
- Kimi usage 的 `cached_tokens` 与 K2.6 公示的 CNY 费率已纳入同一计量模型；
- 对低 RPM 账户新增 Adapter 级 21 秒最小请求间隔及尊重 `Retry-After` 的 20/40/60 秒有界退避；
- MockTransport 已验证 Bearer、URL、模型、固定温度、请求字段、429 退避和无密钥降级边界；
- 先完成 1 样本 DeepSeek/Kimi smoke，随后完成同一 20 样本的 DeepSeek/GLM/Kimi 三模型规范运行；最终 60 次正式 LLM 请求全部成功。

规范结果在 `artifacts/experiments/llm-comparison/`：Kimi 为 20/20 usage 可用、10 TP/0 FP/10 TN/0 FN、F1=1.0，3,677 prompt + 1,019 completion = 4,696 Token，估算 0.0347383 CNY。密钥只保存在本地 `.env`，不进入 artifact、日志或文档。

最终门禁：Python `442 passed`（仅 1 个第三方弃用警告），前端 lint/build 通过；3 个已配置密钥在 `.env` 外精确命中 0，带边界的通用 Key 模式命中 0，规范 artifact 中 Key/HTTP Authorization Header 命中 0；`.env.example` 仍为空占位符，`.gitignore` 明确排除 `.env`。一键演示已刷新，`llm_only:kimi` 被当前 manifest 哈希标记为 `current`。

## 11. Part 9：前端演示与本地样本导入加固（已完成）

### 11.1 本地文件导入闭环

- 新增 `POST /api/uploads` 与 `/uploads`：浏览器使用原始二进制请求体上传，不增加 multipart 依赖；
- 单文件上限 16 MiB；源文件只接受 C（`.c/.h`）、Python（`.py`）、Go（`.go`），二进制必须通过真实 ELF 或 PE magic 校验；
- 文件名会去除路径并规范化，落盘到 `artifacts/uploads/<随机 ID>/`，接口只返回路径、格式、大小和 SHA-256，不返回或记录密钥；
- 前端保留“手动相对路径”方式，同时新增“浏览本地文件”；选择完成后路径自动回填、创建 Task 并自动运行完整分析；
- 上传本身不授予动态执行权限。ELF/PE 上传默认只做静态/逆向分析，仍受原有 Fuzz authorization gate 保护；
- 新增自动识别/C/Python/Go 语言选项，消除了自定义 Python 路径被错误标成 C 的展示问题。

### 11.2 交互与展示修复

- 六阶段流水线改为统一尺寸、边框和排版：到达的阶段显示 `✓ 已完成`，未进入的阶段显示 `○ 未执行`；源码任务中的“动态模糊”未执行是授权策略，不是功能缺失；
- 顶部导航在 1440px 等常见投影分辨率改用独立的横向导航行，Lucide 图标不再被压缩成点或把中文挤成竖排；
- “切换并分析”在任务切换和多次 React 刷新期间保存滚动位置；Playwright 实测点击前后 `scrollY=600 -> 600`；
- 已完成任务的 Dashboard、Navbar、Topology 和命令面板执行按钮统一禁用并显示完成状态，避免重复运行产生 HTTP 409；
- 非终态 Task 不再提前请求报告，消除了正常创建阶段的 `/report` 404 控制台噪声；错误会显示为页面提示，而不是只写入开发者控制台；
- Evidence 页面把普通证据显示为“证据可靠度”，Verification Evidence 优先显示结构化复核置信度，避免把 `reliability=0.5` 错读成复核结论 50%；
- 修复字符串中显示字面量 `&bull;`、前端 V0.2/V0.3/V0.4 混显、离线报告 `CWE CWE-xx`、终态报告仍显示 `reporting` 和仓库内绝对路径等展示问题；
- Vite 忽略 Playwright trace、pytest 临时目录和生成 artifacts，避免浏览器测试产物触发无限页面刷新。

### 11.3 验证结果

- Playwright 真实上传 `samples/source_demo/vulnerable.py`：上传 201、Task 创建 201、运行 200、Finding/Evidence/Report 查询均 200，路径自动回填且自动分析完成；
- Playwright 1440×1000 目视检查：顶部图标清晰、对齐正常，六阶段卡片风格统一；
- 本轮离线 V0.4 Source/Binary/Fuzz HTML/PDF/JSON 已重新生成；Source 报告显示终态 `completed`、仓库相对路径且不再重复 CWE 前缀；
- 上传/API/报告目标回归：8 passed；
- 全量 Python：445 passed，只有 1 个 Starlette/AnyIO 第三方弃用警告；
- `npm run lint` 与 `npm run build`：通过。

三个真实 LLM Provider 仍位于统一 Adapter/Router 边界后，同一业务 Agent 可替换 Provider；主界面展示的是多智能体工作流，不把 DeepSeek、GLM、Kimi 伪装成三个业务 Agent。三模型对比的前端专页尚未开发，规范结果继续以 `artifacts/experiments/llm-comparison/summary.md`、`metrics.json` 和 `run_manifest.json` 展示。

## 12. 安全与交付提醒

- `.env` 含真实 API 凭据，不得提交、截图、写入报告或打包；
- `.env.example` 只能保留占位符；
- 真实密钥曾在对话中明文出现，最终交付前建议轮换；
- 未知二进制不得在宿主系统直接执行；
- 任何“检测率 100%”都必须带上样本规模、置信区间和适用边界；
- 当前工程目录没有检测到 Git 元数据，不能用 Git 状态替代变更审计。
