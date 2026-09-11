# VulnAgent V0.4 高级功能开发规划

> 编写日期：2026-09-11  
> 适用基线：VulnAgent V0.3，Python 全量测试 `396 passed`；当前 V0.4 最终门禁见续接说明  
> 目的：在不破坏现有验收稳定版的前提下，规划 ELF、操作系统级 Fuzz 隔离、Benchmark 扩展及其他增强项。  
> 原始约束：规划建立时 Plus 5 小时窗口剩余约 27%；该阶段决策已执行完毕。

> 进度更新：优先级矩阵第 2 项 Part 6B、第 4 项真实 ELF-A、第 6 项 LLM Usage/Token/Cost、第 10 项 Kimi 第三 Provider 真实三模型实验，以及 Part 9 前端演示/本地样本导入加固均已完成。结果与完整门禁见 `VulnAgent_V0.4_开发续接说明.md`。

## 1. 原始排序与执行结论

推荐顺序：

```text
冻结 V0.3 稳定版
→ 扩大 Benchmark 与样本台账
→ 基于新 Benchmark 改进 Stripped 二进制召回
→ 修复 Linux/WSL 环境并补真实 ELF 实验
→ 报告导出和一键演示增强
→ 操作系统级 Fuzz 沙箱
→ 其他长期增强
```

规划建立时只剩约 27% 用量，因此当时**最推荐先开发“Benchmark 扩展第一阶段”**，不推荐先做操作系统级 Fuzz 沙箱。该决策已经执行，以下原因和额度分配作为历史记录保留。

原因：

- Benchmark 扩展不需要修改冻结公共 Schema；
- 可以复用现有实验脚本，改动范围清楚；
- 能直接增强测试分析报告、PPT 和答辩可信度；
- 新样本可以暴露系统真实缺陷，避免继续针对现有 12 个简单样本过拟合；
- 每增加一组样本都可以独立提交和停止，不容易留下半成品；
- 操作系统级沙箱涉及 Windows Job Object、文件权限、进程树、网络隔离和平台差异，当时剩余用量不足以安全完成并全面回归；
- ELF 基础解析已经存在，而当前 WSL Ubuntu 无法正常启动，错误为 `WSL_E_DISK_CORRUPTED`，此时先写真实 ELF 编译链容易被环境阻塞。

建议把剩余用量大致分配为：

- 约一半用于 Benchmark 扩展的一个完整小阶段；
- 至少三分之一保留给测试、错误修复、文档和交接；
- 剩余部分作为意外回归缓冲。

不要把用量消耗到接近 0 后才运行全量测试。

## 2. 开发前置条件

开始任何 V0.4 修改前必须：

1. 复制并压缩当前 V0.3 验收稳定版；
2. 从稳定版复制出独立的 `VulnAgent_V0.4_高级功能开发版`；
3. 排除 `.env`、`.venv`、`node_modules` 和缓存；
4. 保留 `artifacts/demos/` 与 `artifacts/experiments/` 的规范结果；
5. 记录基线测试：`396 passed`、前端 lint/build 通过；
6. 后续开发只在 V0.4 副本中进行；
7. 不修改 `Task`、`AgentMessage`、`VulnerabilityCandidate`、`Evidence` 冻结协议，除非先完成完整影响分析。

任何高级功能都继续遵守：

- 发现模块不得直接输出 `CONFIRMED`；
- 只有 Verification 可以确认或拒绝漏洞；
- 所有正式结果必须关联 Evidence；
- 未授权目标不得动态执行；
- 不生成面向公网或第三方系统的攻击载荷；
- 不把“策略声明”写成“操作系统已强制执行”。

## 3. 优先级矩阵

| 排名 | 增强项 | 当前状态 | 课程/PPT收益 | 开发风险 | 当前是否推荐 |
|---:|---|---|---|---|---|
| 1 | Benchmark 扩展第一阶段 | 已完成：20 Source、14 Binary、1 Fuzz 场景 | 很高 | 已收敛 | 完成 |
| 2 | 加壳/混淆授权样本台账 | 已完成：2+2 样本、严格门禁与 Part 6B 静态实测 | 很高 | 已收敛 | 完成 |
| 3 | Stripped 二进制召回改进 | 已完成：14 样本下 Recall/F1=1.0 | 高 | 已收敛 | 完成 |
| 4 | 真实 ELF Benchmark/Demo | ELF-A 已完成：6 Fixture × 3 Profile = 18 条 | 中至高 | 已由 Zig 交叉编译解决 | 完成 |
| 5 | HTML/PDF 报告导出和一键演示 | JSON/Markdown/HTML/PDF 一键离线演示包已完成 | 高 | 已收敛 | 完成 |
| 6 | LLM usage/token/cost 记录 | 已完成：供应商 usage、版本化费率、分币种估算与真实 60 调用 | 中 | 已收敛 | 完成 |
| 7 | Windows Job Object 资源隔离 | 已完成并通过 CPU/内存/进程数实测 | 高 | 已收敛 | 完成 |
| 8 | 真正网络/文件系统隔离 | 当前仅有策略声明 | 高 | 很高 | 独立版本开发 |
| 9 | 跨进程 Agent checkpoint | Task/Evidence 可恢复，运行中 checkpoint 不恢复 | 中 | 高 | 长期增强 |
| 10 | 第三个 LLM/Kimi | 已完成：Adapter/配置/限流兼容/契约测试与 20 样本真实实测 | 低 | 已收敛 | 完成 |
| 11 | 前端演示与本地样本导入加固 | 已完成：受限上传、自动分析、阶段/导航/滚动/错误反馈统一 | 高 | 已收敛 | 完成 |

## 4. 第一优先级：扩大 Benchmark

### 4.1 目标

将“当前样本上 F1 很高”升级为“面对更难写法和安全反例时，系统仍能诚实报告能力边界”。

重点不是盲目增加数量，而是增加能够区分真实分析能力和规则记忆的样本。

### 4.2 第一阶段建议范围

在剩余用量有限时，只完成以下小阶段：

```text
新增 8 个 Source 样本
├─ 4 个漏洞样本
└─ 4 个困难安全反例

新增 4 个 Binary C 样本
├─ 2 个漏洞样本
└─ 2 个近似安全反例

扩展 manifest、契约测试和实验文档
重新运行 Source/Binary 指标
暂不重复付费 LLM 全量实验
```

### 4.3 Source 样本设计

建议新增：

1. 跨函数参数传递到 `subprocess` 危险调用；
2. 包装函数内部的 SQL 字符串拼接；
3. 路径在 helper 中规范化但调用点较远的安全反例；
4. `shell=False` 且参数列表固定的困难安全反例；
5. `yaml.safe_load` 经别名导入的安全反例；
6. `eval` 名称被局部安全函数遮蔽的安全反例；
7. 经过简单 sanitizer 后进入 sink 的样本；
8. 两个文件之间的数据流样本。

每个漏洞样本必须有对应或近似对应的安全反例，避免只增加容易命中的危险 API 字符串。

### 4.4 Binary 样本设计

建议新增：

1. 危险函数经过一层 wrapper 调用；
2. 函数指针或导入修饰名变体；
3. `snprintf`/长度检查的困难安全反例；
4. 名称包含 `system`、`strcpy` 但实际不是危险函数的反例。

所有样本继续使用 Symbol-Rich/Stripped 成对编译。检测器不得读取 Ground Truth、样本 ID 或源文件路径来产生答案。

### 4.5 Manifest 要求

每个样本至少记录：

- `sample_id`；
- 相对路径；
- 来源和许可证；
- 是否为项目自研；
- 明确授权；
- Ground Truth；
- CWE；
- 预期 Finding 类型；
- 构建或运行命令；
- 是否允许执行；
- 样本家族或变体 ID。

建议增加“样本家族”概念用于数据拆分，但不要擅自修改冻结公共 Schema；它只属于 Benchmark manifest。

### 4.6 防止数据泄漏和过拟合

- 同一模板的漏洞版和安全版不能分别进入训练提示和测试集；
- LLM Prompt 不发送 Ground Truth、CWE 答案或文件夹中的 `vulnerable/clean` 标签；
- Analyzer 不得读取 manifest；
- 样本路径不要成为规则条件；
- 新样本应先冻结，再修改分析器；
- 即使指标下降也应保留结果，不应删除失败样本来恢复 100%。

### 4.7 第一阶段 Definition of Done

- 新增样本均有许可证、授权和 Ground Truth；
- Manifest 校验测试通过；
- Source 和 Binary 实验能完整生成四类产物；
- `metrics.json` 与文档数字一致；
- 新样本没有被执行，除非属于显式授权 Fuzz；
- 全量 Python 测试通过；
- 前端 lint/build 不受影响；
- 文档明确记录新增误报、漏报及原因；
- 不为了保持满分而硬编码样本答案。

## 5. 加壳与混淆样本增强

进度：Part 6A 准入 manifest、路径/来源/授权/哈希门禁和 readiness 产物已完成；4 个不同的授权教育逆向挑战已经物化，严格结果为 2/2 + 2/2，Part 6B 静态实测已完成。

### 5.1 为什么重要

课程原文要求支持任意 2 种具备加壳功能的闭源软件，以及任意 2 种具备混淆功能的闭源软件。当前系统已经有 Packer/Obfuscation 能力和 UPX/radare2 Adapter，但现有自研 Binary Benchmark 不能严格证明该验收要求已经完成。

### 5.2 推荐实施方式

先建立样本台账，不要先写检测规则：

```text
benchmarks/packed/manifest.json
benchmarks/obfuscated/manifest.json
```

每个样本必须记录：

- 软件名称和版本；
- 获取来源；
- 使用授权；
- SHA-256；
- 平台与架构；
- 壳/混淆器及版本；
- 是否允许静态分析；
- 是否允许动态执行；
- 预期可观测特征；
- 工具执行记录和降级路径。

### 5.3 安全边界

- 只使用自己拥有、开源许可或得到明确授权的样本；
- 未确认授权时只做文件哈希和静态元数据检查；
- 不执行来源不明的闭源程序；
- 不下载恶意软件作为课程演示材料；
- 不把两个不同打包参数生成的同一程序冒充两个不同软件；
- 如果老师允许自研程序的加壳版本作为教学样本，应在报告中明确说明，不写成真实闭源商业软件。

### 5.4 DoD

- 至少 2 个加壳样本和 2 个混淆样本；
- 每个样本都有来源、授权和哈希；
- 检测过程产生结构化 Evidence；
- 失败和不确定结果同样保留；
- Verification 不越权确认；
- 报告中能够区分“检测到加壳特征”和“成功去壳”；
- 报告中能够区分“检测到混淆特征”和“恢复出可靠伪代码”。

## 6. Stripped 二进制召回改进

### 6.1 当前问题

Part 1 基线中 Binary Symbol-Rich 组 F1=1.0；Stripped 组 F1=0.889（Recall=0.800）。Part 2 已通过 PE x64 调用点参数语义将 Stripped Recall/F1 提高到 1.0，同时在扩展至 14 个样本后保持 FPR=0。

### 6.2 为什么要放在 Benchmark 之后

如果先看着当前唯一漏报直接编写特例，很容易把测试样本信息写进规则。先增加 wrapper、近似函数和安全反例，才能验证改进是否真的泛化。

### 6.3 推荐技术路线

1. 定位对共享 CRT helper 的调用点；
2. 提取调用前参数数量、常量长度和目标缓冲区上下文；
3. 识别 IAT/PLT、重定位和可恢复的调用目标；
4. 将“精确符号”“调用点语义”“启发式推断”分级记录；
5. 低可观测性时保持 `UNCERTAIN`；
6. 不使用文件名、目录名或 Ground Truth。

### 6.4 DoD

- Stripped `sprintf` 召回提高；
- `snprintf` 安全反例仍保持零误报；
- 至少增加 2 个新的近似反例；
- 每个启发式结论记录 Evidence 来源和限制；
- Symbol-Rich/Stripped 对比可重现；
- 不改变 Verification-only confirmation。

## 7. ELF 扩展规划

### 7.1 不是从零开发

当前静态解析器已经支持：

- ELF32/ELF64；
- 大端/小端；
- Header、Section、Segment；
- SYMTAB/DYNSYM；
- 导入、导出和已声明函数；
- 扩展节区编号、NOBITS 和资源限制；
- 合成 ELF 契约测试。

因此后续任务应命名为“真实 ELF Benchmark 与 Stripped ELF 增强”，而不是再次实现一个 ELF 魔数解析器。

### 7.2 ELF-A 后的剩余缺口

- 已有 Zig `x86_64-linux-gnu` 真实构建的规范 Demo，但尚未补 Linux GCC 的交叉验证；
- PE 与 ELF 已分别统计，但尚未形成逐样本跨平台差异表；
- 无节区表时尚未从 `PT_DYNAMIC` 恢复动态符号；
- 尚未系统解析 GOT/PLT 与重定位；
- 内置解析器不反汇编 ELF 可执行段；
- 缺少 Windows/Linux CI 矩阵。

### 7.3 环境问题与已采用方案

本机 WSL2/Ubuntu 仍因 `WSL_E_DISK_CORRUPTED` 无法启动。没有修改发行版数据，而是下载并校验官方 Zig 0.16.0 Windows x64 发行包，使用 `zig cc -target x86_64-linux-gnu` 生成真实动态链接 ELF，因此 ELF-A 指标已可在 Windows 宿主复现。

修复 WSL 可能涉及发行版数据，必须先备份并由用户明确决定；不要自动注销、重装或删除 WSL 发行版。

### 7.4 分阶段实现

#### ELF-A：真实只读 Benchmark

- 使用 Zig 交叉编译现有 6 个 C 样本；（已完成）
- 生成 Symbol-Rich、Stripped、PIE 三个 Profile；（已完成）
- 目标只读分析，不执行；
- 记录 compiler、flags、SHA-256 和 ELF 架构；
- 与 Windows PE 结果分别统计。

#### ELF-B：PT_DYNAMIC 与重定位

- 在无节区表或节区信息不足时解析 `PT_DYNAMIC`；
- 有界读取 `DT_NEEDED`、`DT_STRTAB`、`DT_SYMTAB`；
- 解析常见 x86_64 GOT/PLT relocation；
- 所有偏移、数量和字符串长度受资源上限约束；
- 损坏 ELF 必须安全失败。

#### ELF-C：反汇编与函数候选

- 只反汇编标记为 executable 的文件区间；
- 使用 Capstone Adapter，业务层不直接依赖第三方实现；
- 区分符号声明函数与启发式函数候选；
- 不把线性反汇编伪装成完整 CFG；
- 地址统一记录为链接时虚拟地址或文件偏移，并明确语义。

### 7.5 DoD

- 至少覆盖 x86_64 ET_EXEC、PIE/ET_DYN 和 Stripped ELF；
- 同一源码在 PE/ELF 上可成对比较；
- 无节区或损坏输入不会越界、崩溃或无限解析；
- 目标从不执行；
- Binary Agent、Verification、Evidence、Report 主链完整；
- Linux 环境和编译器版本写入 run manifest；
- 现有 PE 测试全部通过。

## 8. 操作系统级 Fuzz 沙箱规划

### 8.1 当前真实状态

跨平台 `SubprocessBackend` 已具备：

- `shell=False`；
- 超时；
- 基础进程树终止；
- stdout/stderr 上限；
- Runtime Trace；
- 显式授权检查。

Windows 默认 `WindowsJobBackend` 已强制：

- Kill-on-job-close；
- Active Process Limit；
- Process/Job Memory Limit；
- Job CPU Time Limit，并由内核 accounting guard 补充确定性终止；
- 目标在挂入 Job 前保持 suspended，失败时不静默降级；
- 资源终止与真实 Crash 分离。

以下字段仍没有全部由操作系统强制：

- `network_enabled=False`；
- `writable_dirs`/`readonly_dirs`；
- `max_file_size_mb`。

Windows Job Object 不是网络或文件系统隔离器；Linux/macOS 当前仍使用能力较弱的 subprocess 后端。

### 8.2 必须分清三类隔离

| 隔离类型 | Windows Job Object 能否单独完成 |
|---|---|
| CPU、内存、活动进程数、关闭时杀进程树 | 可以 |
| 文件系统白名单/只读挂载 | 不可以完整完成 |
| 禁止网络或只允许指定主机 | 不可以 |

因此“实现 Job Object”不能被写成“实现完整沙箱”。

### 8.3 推荐架构

```text
SandboxManager
├─ SubprocessBackend（开发模式，能力有限）
├─ WindowsJobBackend（资源和进程树限制）
└─ IsolatedWorkerBackend
   ├─ Windows Sandbox / Hyper-V
   └─ Linux namespace / container
```

每次结果应记录：

- `backend_name`；
- `enforced_controls`；
- `unsupported_controls`；
- `network_isolation_enforced`；
- `filesystem_isolation_enforced`；
- 资源限制值；
- 超时和终止原因。

这些信息应进入 Fuzz Evidence 或 Runtime Trace，但不要修改冻结 Evidence Schema；优先放入现有 metadata。

### 8.4 Sandbox-A：Windows Job Object

状态：**已完成（2026-09-11）**。

实现范围：

- Kill-on-job-close；
- Active Process Limit；
- Process/Job Memory Limit；
- CPU Time Limit；
- 子进程继承；
- 超时后完整回收；
- 不可用时 fail closed 或显式标记降级。

规范 Fuzz 产物的 `run_manifest.json` 和每次 Runtime Evidence 均记录 backend、enforced/unsupported controls 与资源限制；相关实测覆盖正常执行、活动进程限制、忙循环 CPU 限制和大内存分配。

禁止：

- 静默回退到无资源限制执行；
- 声称 Job Object 已禁止网络；
- 使用字符串拼接 Shell 命令；
- 在测试中执行未知二进制。

### 8.5 Sandbox-B：网络与文件系统隔离

优先选择一次性隔离 Worker，例如 Windows Sandbox/Hyper-V 或 Linux namespace/container。不要通过全局修改宿主机防火墙来模拟单任务隔离，避免影响用户系统。

该阶段需要：

- 临时工作目录；
- 最小只读输入挂载；
- 单独可写输出目录；
- 默认无网络；
- 任务结束自动销毁；
- 资源配额；
- Worker 与主程序之间只交换结构化请求和结果；
- 样本文件哈希和授权记录。

### 8.6 沙箱测试

只使用自研无害测试程序验证：

- 正常退出；
- 超时；
- 子进程树；
- 超量内存；
- 超量进程；
- 超量输出；
- 越界写文件；
- 尝试连接本机测试端口；
- Backend 不可用；
- Worker 异常退出。

测试目标是证明限制是否真正生效，不包含恶意持久化、提权或公网连接。

### 8.7 DoD

- 每个声称的限制都有实际失败测试；
- 网络隔离有操作系统级验证，而不是读取 Policy 布尔值；
- 子进程不会在任务结束后残留；
- 不影响宿主机全局网络和防火墙；
- Backend 不可用时默认不执行目标；
- 运行证据明确列出已强制和未强制控制；
- 文档、UI 和报告不夸大隔离能力；
- 全量回归通过。

## 9. 报告导出与一键演示增强

状态：**已完成（2026-09-11）**。

### 9.1 HTML 报告导出

`src/vulnagent/report/html.py` 已把现有结构化 `ReportResult.content` 投影为独立 HTML，包含：

- 任务和目标摘要；
- 漏洞列表与严重度；
- Finding 状态；
- Evidence 链；
- Verification 结论；
- 修复建议；
- 工具降级和系统限制；
- 生成时间与样本哈希。

所有内容从现有 Task/Finding/Evidence/Verification/Report 读取，没有创建第二套漏洞 Schema。页面自包含、无脚本和外部资源，使用 CSP 与上下文转义处理不可信文本，并采用临时文件原子替换写出。

### 9.2 PDF 与一键离线演示包

`src/vulnagent/report/pdf.py` 使用可选 ReportLab 依赖生成可打印 PDF，采用 CID 中文字体，保留 Finding、Evidence、独立复核、修复建议、时间线、限制和分页信息。缺少依赖时明确失败，也可通过 `--skip-pdf` 只生成 JSON/HTML。

`scripts/demo_v04.py` 现在用一条命令生成 Source/Binary/Fuzz 三条正式主链的：

- 3 份 JSON；
- 3 份离线 HTML；
- 3 份 PDF；
- `index.json` 与带可点击报告链接的 `summary.md`。

该入口不读取或显示 API Key，也不会发起外部 LLM 调用。它是本优先级中的“一键演示”：强调可复现地产生与打开离线实物，不等同于 EXE，也不依赖前后端服务启动。

独立导出入口为 `scripts/export_report_html.py` 和 `scripts/export_report_pdf.py`。完整复现命令：

```powershell
.\.venv\Scripts\python.exe scripts\demo_v04.py --output-dir artifacts\demos\v04
```

### 9.3 验收结果与边界

- Source HTML 实测完整显示 4 个 Finding、20 条 Evidence、独立复核和修复建议；
- 最终静态服务器下浏览器控制台 0 error / 0 warning，恶意样式文本转义测试通过；
- Source/Binary/Fuzz PDF 分别为 6/2/4 页，均通过 PDF 解析，Source 首页另经真实渲染目视检查；
- 本轮最终全量 Python：442 passed；前端 lint/build：通过；排除 `.env` 后的凭据扫描：0 命中；
- 冻结公共 Schema 未修改，Finding 的确认边界仍由 Verification 独占；
- 自动启动前后端、自动打开浏览器、EXE/安装包和 PPTX 属于不同交付便利项，本轮没有启动。

## 10. LLM 指标增强（已完成）

当前实现已记录 Provider、模型、延迟、分类标签、响应哈希、供应商 Token usage、缓存命中和分币种估算 Cost。

已经实现非破坏性结果对象：

```text
LLMResponse
├─ text
├─ usage.prompt_tokens
├─ usage.cached_prompt_tokens
├─ usage.completion_tokens
├─ usage.total_tokens
├─ usage.cost
├─ usage.currency
└─ usage.cost_is_estimate
```

注意：

- 不记录 API Key、Authorization Header 或完整请求头；
- 不保存模型隐藏思维链；
- 厂商没有返回的字段保持 `null`；
- Cost 根据运行时价格配置计算时，必须记录价格表日期和来源；
- `generate_with_usage` 保持现有 `BaseLLM.generate -> str` 调用者兼容。

真实 20 样本结果：DeepSeek 5,248 Token / 0.002317218 USD（weekday-peak 估算），GLM 5,803 Token / 0.069904 CNY（估算），Kimi 4,696 Token / 0.0347383 CNY（估算，其中缓存输入 3,088）。费用来源、日期、费率档位、请求控制和币种写在 run manifest；账户账单仍是最终依据。

## 11. 持久化与可恢复运行增强

当前 SQLite 已能恢复 Task、Evidence 和最终 AnalysisContext，但运行中 Agent checkpoint 与 EventBus 历史尚未完整跨进程恢复。

长期计划：

- 运行步骤 checkpoint；
- 幂等 Agent 执行键；
- 任务中断后从最后安全节点恢复；
- Event/Message 持久化；
- 重复消息去重；
- Schema 版本迁移；
- 恢复后仍遵守最大步骤和重复路由限制。

该功能改动 Core、Runtime 和 Storage 多个模块，风险较高，不适合原先的 27% 用量窗口。

## 12. UI 高级增强

只有在后端数据真实存在时才增加 UI：

- 实验对比页：直接读取规范 `metrics.json` 或后端实验 API；
- Evidence 图：Finding、Evidence、Verification 的可交互关系；
- 二进制函数和地址视图；
- Fuzz 执行预算、触达路径和 Crash 指纹；
- Sandbox 控制状态：区分 enforced、declared、unsupported；
- HTML Report 下载。

禁止恢复虚构的覆盖率、吞吐率、ASAN、AFL++ 或架构信息。UI 没有真实数据时显示 `N/A`。

## 13. CI 与供应链增强

长期建议：

- Windows + Linux 测试矩阵；
- Linux 上真实编译 ELF Fixture；
- Python/Node 依赖锁定和漏洞审计；
- 生成 SBOM；
- 检查 `.env` 和常见密钥格式；
- 检查实验 Artifact 不含密钥；
- 上传测试和 Benchmark 指标 Artifact；
- 不在 CI 中默认调用付费 LLM；
- 真实 Provider 测试使用手动工作流和受保护 Secret。

## 14. 建议的版本拆分

```text
V0.3.1  Delivery Hardening
├─ 扩大 Benchmark 第一阶段
├─ 加壳/混淆样本台账
├─ 文档和实验更新
└─ HTML 报告或一键演示

V0.4  Cross-Platform Binary
├─ 真实 ELF Benchmark
├─ PT_DYNAMIC / GOT / PLT
├─ Stripped 函数召回
└─ Windows/Linux 对比

V0.5  Enforced Sandbox
├─ Windows Job Object
├─ 隔离 Worker
├─ 网络/文件系统隔离
└─ 沙箱证明实验

V0.6  Resumable Runtime
├─ Agent checkpoint
├─ Event 持久化
└─ 中断恢复
```

不要在同一个版本中同时修改 Binary、Sandbox、Runtime、Storage 和 UI；这会使回归定位和答辩解释都变得困难。

## 15. 原 27% 用量决策的执行结果

### 已完成

原建议闭环已经完成：

```text
扩展 8 个 Source + 4 个 Binary Benchmark
→ 冻结 manifest
→ 补 manifest 测试
→ 运行现有分析器
→ 记录新增误报/漏报
→ 只修明显通用缺陷
→ 全量回归
→ 更新评测文档和续接说明
```

此后又依次完成 Stripped 召回、ELF 环境无关 runner、Windows Job 资源沙箱、受保护样本准入门禁、JSON/Markdown/HTML/PDF 一键离线演示包、四样本 Part 6B 静态实测，以及 Zig 真实 ELF-A Benchmark，且每个 Part 均保留独立实验和回归记录。

### 仍不应混淆的边界

- 不把已完成的 Windows Job 资源限制称为网络或文件系统隔离；
- 不自动修复或重装 WSL；
- 不同时扩展 ELF、Sandbox 和 UI；
- Kimi 成绩只引用 `artifacts/experiments/llm-comparison/` 的 20 样本规范产物，不引用 smoke 或失败批次；
- 不重跑全部付费 LLM 实验，除非 Benchmark 已最终冻结；
- 不为了 PPT 数字好看删除失败样本或降低 Ground Truth 难度；
- 不修改冻结公共 Schema。

### 如果用量进一步下降

当剩余用量不足以覆盖实现、测试和文档三个阶段时，应停止编码，只完成：

1. 样本设计清单；
2. Manifest 草案；
3. 风险与验收标准；
4. 新会话续接提示；
5. 稳定版备份检查。

宁可留下边界清楚的规划，也不要在验收稳定版中留下无法回归的半成品沙箱。

## 16. 下一会话建议提示词

```text
请先完整阅读 AGENTS.md、演示help.md、VulnAgent_V0.4_开发续接说明.md 和 VulnAgent_V0.4_高级功能开发规划.md。矩阵第 2 项 Part 6B、第 4 项 ELF-A、第 6 项 LLM Usage/Cost 和第 10 项 Kimi 第三 Provider 均已完成；三模型规范实验位于 artifacts/experiments/llm-comparison。Sandbox-B、ELF-B/C、EXE 和 PPTX 均未启动。不要修改冻结 Schema，不要执行未知或未授权二进制，不要把本地 .env 打包或提交。
```

## 17. 当前决策

**优先级矩阵第 2、4、6、10 项已经完成；Kimi 已通过真实 20 样本、60 请求三模型对比。**

剩余项包括 ELF-B/C、网络与文件系统隔离 Sandbox-B、三模型对比专页、EXE 打包和 PPTX。核心演示界面与本地文件导入已经完成加固，但这不等于完成桌面 EXE 交付。四个教育挑战只证明受保护二进制的准入、静态分析、工具变换、Evidence/Verification/Report 闭环；它们没有漏洞 Ground Truth，不能宣称完成了漏洞利用验证。
