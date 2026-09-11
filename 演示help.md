# VulnAgent 最终交付与现场演示指南

> 适用项目：题目 1“基于大模型智能体的软件漏洞挖掘系统设计与实现”  
> 当前版本：VulnAgent V0.4  
> 验收形式：PPT + 现场作品展示，总时间 15 分钟  
> 本文不包含任何 API Key；演示和提交时禁止打开、录制或打包 `.env`。

## 1. 什么是“最终交付包装”

最终交付包装不是把整个开发目录直接压缩，而是把老师能阅读、运行、复核和归档的内容整理成一个结构清楚的提交包。

课程原文要求提交：

1. 任务分工说明；
2. 作品技术原理介绍；
3. 概要设计报告；
4. 详细设计报告；
5. 测试分析报告；
6. 程序编译和安装使用文档；
7. 程序源代码；
8. PPT；
9. 截屏录像。

压缩包应命名为：

```text
组长班级+组长姓名+学号.zip
```

最终包应做到：

- 解压后能看懂项目结构；
- 按安装文档可以启动；
- 不联网也能查看已经生成的实验结果；
- 能从 Benchmark、运行命令、结果 JSON 和文档互相验证结论；
- 不包含密钥、虚拟环境、依赖缓存和无关临时文件。

## 2. 推荐的提交包目录

建议在仓库外新建下列目录，再复制需要提交的文件，不要直接修改或删除工作仓库：

```text
组长班级+组长姓名+学号/
├─ 01_任务分工说明/
│  └─ 任务分工说明.pdf
├─ 02_作品技术原理/
│  └─ VulnAgent技术原理.pdf
├─ 03_概要设计/
│  └─ 概要设计报告.pdf
├─ 04_详细设计/
│  └─ 详细设计报告.pdf
├─ 05_测试分析/
│  ├─ 测试分析报告.pdf
│  └─ 可复现实验结果/
├─ 06_安装使用/
│  └─ 程序编译安装与使用说明.pdf
├─ 07_程序源代码/
│  └─ VulnAgent/
├─ 08_PPT/
│  └─ VulnAgent课程设计答辩.pptx
├─ 09_截屏录像/
│  └─ VulnAgent完整演示.mp4
└─ 10_可验证实物/
   ├─ demos/
   ├─ experiments/
   ├─ benchmark清单与说明/
   └─ README.txt
```

现有材料与课程文档的对应关系如下：

| 课程材料 | 当前可用内容 |
|---|---|
| 技术原理 | `docs/00_project/project_overview.md`、`docs/00_project/innovation.md` |
| 概要设计 | `docs/01_architecture/system_architecture.md`、`docs/01_architecture/v0.3_integration.md` |
| 详细设计 | `docs/02_protocol/`、各模块 README、公共 Schema 与测试 |
| 测试分析 | `docs/04_evaluation/reproducible_evaluation.md`、`artifacts/experiments/` |
| 安装使用 | 根目录 `README.md`、本文 |
| 当前进度和限制 | `VulnAgent_V0.4_高级功能开发规划.md` |
| 新会话/维护交接 | `VulnAgent_V0.4_开发续接说明.md` |

正式提交时，建议把上述 Markdown 内容整理成格式统一的 PDF，而不是只提交零散 Markdown。

## 3. 哪些文件必须排除

禁止放入提交包或演示录像：

```text
.env
.venv/
node_modules/
.pytest-*/
__pycache__/
*.pyc
开发工具缓存
个人账户、Token、API Key
无关的大型临时二进制
```

应保留 `.env.example`、`pyproject.toml`、`package.json`、`package-lock.json`、源码、测试、Benchmark、文档和经过检查的实验结果。

DeepSeek、智谱与 Kimi 密钥曾用于真实实验，但不得进入提交包。正式实验产物已经检查，不包含密钥。提交前仍应再次执行密钥扫描，并轮换曾经暴露过的密钥。

## 4. 验收前生成“可验证实物”

### 4.1 运行质量门禁

在项目根目录打开 PowerShell：

```powershell
.\.venv\Scripts\python.exe -m pytest -q --basetemp .\.pytest-demo-final
npm run lint
npm run build
```

当前参考结果：Python `445 passed`，前端 lint 和生产构建通过。

### 4.2 重新生成三个正式 Demo

```powershell
.\.venv\Scripts\python.exe scripts\demo_source_v03.py
.\.venv\Scripts\python.exe scripts\demo_binary_v03.py
.\.venv\Scripts\python.exe scripts\demo_fuzz_v03.py
```

主要实物：

```text
artifacts/demos/binary-v03.json
artifacts/demos/fuzz-v03.json
```

Binary Demo 需要本机可用的 `gcc` 或 `cc`。如果教室电脑没有编译器，应提前在自己的演示电脑生成 `artifacts/demos/binary-demo.exe`。现场可使用：

```powershell
.\.venv\Scripts\python.exe scripts\demo_binary_v03.py --target artifacts\demos\binary-demo.exe
```

### 4.3 保留四组实验结果

建议提交以下目录：

```text
artifacts/experiments/source-ablation/
artifacts/experiments/binary-benchmark/
artifacts/experiments/fuzz-ablation/
artifacts/experiments/llm-comparison/
```

每组至少应包含：

- `labelled_results.json`；
- `metrics.json`；
- `metrics.csv`；
- `run_manifest.json`。

`run_manifest.json` 用来证明模型、样本清单哈希、Python 版本和生成时间；`metrics.json` 用来证明报告中的数字不是手工填写。

真实 LLM 全量实验不要在现场重复运行。它依赖网络、会产生费用，也容易因教室网络波动浪费时间。现场直接展示已经生成的结果和运行清单即可。如果老师明确要求联网验证，可只运行一个样本：

```powershell
.\.venv\Scripts\python.exe -m experiments.run_llm_comparison `
  --manifest benchmarks\manifest.json `
  --providers deepseek glm `
  --max-samples 1 `
  --output-dir artifacts\experiments\llm-live-check
```

执行前必须确认屏幕、终端历史和录屏中不会出现 `.env` 或密钥。

### 4.4 前端本地目标导入演示

在态势大屏的 Benchmark 区域点击“指定自定义审计目标路径”，可用两种方式：

1. 手动填写服务端项目目录中的相对路径，选择 Source/Binary 和源码语言后点击“初始化并开始审计”；
2. 点击“浏览本地文件”，选择一个 `.c/.h/.py/.go` 源文件或真实 ELF/PE 文件。文件会上传到 `artifacts/uploads/<随机 ID>/`，路径自动回填，并立即进入多智能体自动分析。

上传单文件上限为 16 MiB。上传只代表允许静态读取，不代表允许执行；ELF/PE 不会因为上传而绕过 Fuzz 授权门禁。演示源码任务时，第 4 步“动态模糊”显示“未执行”属于正确安全语义；使用授权 Fuzz Demo 时该阶段才显示“已完成”。

## 5. 现场演示前的启动方法

推荐先运行 V0.4 一键入口：

```powershell
.\.venv\Scripts\python.exe scripts\demo_v04.py --output-dir artifacts\demos\v04
```

该命令运行 Source、Binary 和明确授权的本地 Fuzz Demo，并生成：

- `artifacts/demos/v04/summary.md`：答辩时优先展示的短摘要；
- `artifacts/demos/v04/index.json`：带实验批次兼容性状态的机器可读索引；
- `source.json`、`binary.json`、`fuzz.json`：三条现场主链的完整结构化报告；
- `source.html`、`binary.html`、`fuzz.html`：无需启动前后端即可打开的离线报告；
- `source.pdf`、`binary.pdf`、`fuzz.pdf`：可打印和提交的分页报告。

它不会调用任何外部 LLM；当前 20 样本 LLM、真实 ELF 和 Part 6B 快照会在 manifest 哈希一致时标成 `current`。如果现场不允许动态执行，添加 `--skip-fuzz`，只演示 Source/Binary 只读路径；没有安装 `report-export` 依赖时可用 `--skip-pdf`，但正式交付建议保留 PDF。

### 5.1 启动后端

第一个 PowerShell 窗口：

```powershell
cd "E:\BUPT\3_Cyberspace Security_1\VulnAgent-develop"
.\.venv\Scripts\python.exe -m vulnagent.main
```

验证：

```text
http://127.0.0.1:8000/api/health
http://127.0.0.1:8000/docs
```

### 5.2 启动前端

第二个 PowerShell 窗口：

```powershell
cd "E:\BUPT\3_Cyberspace Security_1\VulnAgent-develop"
npm run dev
```

浏览器打开：

```text
http://127.0.0.1:5173
```

建议进入教室前就启动后端和前端，并提前打开以下内容：

1. VulnAgent Dashboard；
2. FastAPI `/docs`；
3. `artifacts/experiments/llm-comparison/metrics.json`；
4. `artifacts/experiments/fuzz-ablation/metrics.json`；
5. `artifacts/experiments/binary-benchmark/metrics.json`；
6. 三个 Demo 的 PowerShell 窗口。

不要在现场临时安装依赖、下载模型或首次编译全部样本。

## 6. 推荐的 15 分钟演示流程

总时间只有 15 分钟，建议按“4 分钟 PPT + 8 分钟产品 + 2 分钟实验 + 1 分钟缓冲/问答”组织。

### 0:00—1:00：说明问题与目标

建议开场：

> VulnAgent 不是一次大模型问答，也不是给第三方扫描器换界面。它将程序理解、源码或二进制分析、风险引导 Fuzz、独立漏洞复核、证据链和报告生成拆成职责独立的 Agent，并通过冻结的结构化协议统一编排。

只讲三点：

- 输入同时支持源代码和二进制程序；
- 发现 Agent 没有权限直接确认漏洞；
- 所有正式结果必须关联 Evidence。

### 1:00—2:30：展示系统架构

展示主流程：

```text
Target
→ Planner
→ Source Audit / Binary Analysis
→ Guided Fuzz（显式授权时）
→ Verification
→ Reviewer
→ Evidence Chain
→ Report
```

强调：Agent 通过 `AgentMessage` 通信；Supervisor 有最大步数、重复路由限制和确定性回退；只有 Verification 能写入 `CONFIRMED` 或 `REJECTED`。

### 2:30—4:00：说明创新点

建议只讲三个可实验验证的创新点：

1. **Evidence First + Independent Verification**：模型自然语言不能单独证明漏洞；
2. **静态风险引导动态 Fuzz**：在相同执行预算下比较 Guided 与 Random；
3. **二进制可观测性实验**：用 Symbol-Rich/Stripped 成对样本量化去符号后的召回损失。

### 4:00—7:30：主演示——源码任务

在 Dashboard 新建任务：

```text
目标路径：samples/source_demo
目标类型：source
```

运行后按顺序展示：

1. **Dashboard**：任务从创建到完成，不展示硬编码遥测；
2. **Agent Topology / Event Trace**：指出 Planner、Source Audit、Verification、Reviewer、Report 的实际路由；
3. **Vulnerabilities**：展示漏洞类型、CWE、位置、置信度和状态；
4. **Evidence Chain**：从 Finding 跳到源码位置、代码片段、数据流和复核证据；
5. **Verification**：强调发现模块先输出 `CANDIDATE`，之后才由独立验证变为 `CONFIRMED`；
6. **Report**：展示漏洞列表、严重度、证据和修复建议。

当前参考结果是 4 个 Confirmed Findings、20 条 Evidence，复核置信度均值约 86%。现场应以实际界面为准，不要死记数字；如果结果变化，直接解释新的真实结果。

### 7:30—9:00：二进制分析

运行或展示已经生成的结果：

```powershell
.\.venv\Scripts\python.exe scripts\demo_binary_v03.py --target artifacts\demos\binary-demo.exe
```

重点解释：

- Reverse、Logic、Obfuscation 通过正式 Runtime 接入；
- 系统读取 PE/ELF 头、导入、函数、字符串和反汇编 Evidence；
- 分析过程不执行目标二进制；
- 单一静态证据不足时结果为 `UNCERTAIN`，这是防止误报的设计，不是运行失败。

当前参考结果为 1 个 Finding、4 条 Evidence，Verification 结论为 `UNCERTAIN`。

### 9:00—10:30：风险引导 Fuzz

运行：

```powershell
.\.venv\Scripts\python.exe scripts\demo_fuzz_v03.py
```

重点解释：

- 仅运行项目自研、显式授权的本地教学靶标；
- `fuzz_authorized` 与 `dynamic_validation` 必须同时为真；
- Source Audit 的结构化风险提示用于生成非 Exploit 边界探针；
- Crash 被转换为 `CRASH_LOG` Evidence，再交给 Verification；
- 当前 subprocess 只提供进程级边界，不能宣称实现了完整虚拟机或操作系统级断网。

### 10:30—12:30：展示可复现实验

建议在一个表格中只展示下列结果：

| 实验 | 对照结果 | 应当得出的结论 |
|---|---|---|
| Verification OFF/ON | 20 个 Source 中，OFF 不产生 Confirmed；ON 确认 10 个真实风险候选 | 独立复核确实改变最终 Verdict |
| Random/Guided Fuzz | 同为每轮 80 次执行，Guided 10/10 触达，Random 0/10 | 静态风险能够提高受控路径触达率 |
| Binary Symbol-Rich/Stripped | 14 个 Binary 中 F1 均为 1.0，FPR 均为 0 | 调用点参数语义恢复去符号后的 `sprintf` 漏报，并通过两组新增近似反例约束 |
| DeepSeek/GLM/Kimi/VulnAgent | 当前 20 样本 F1 均为 1.0；三个 LLM-only Evidence Coverage=0，VulnAgent=1.0 | 分类已饱和，系统优势是证据与复核，不是虚构精度领先 |
| LLM Usage/Cost | DeepSeek 5,248 Token / 0.002317218 USD（weekday peak）；GLM 5,803 Token / 0.069904 CNY；Kimi 4,696 Token / 0.0347383 CNY | Token 为供应商返回值，费用按版本化费率估算且币种不相加 |

同时说明：扩展 Source 有 10 个阳性和 10 个阴性，Precision/Recall 的 Wilson 95% 下界约为 0.722，仍不能外推为真实世界 100% 检出率。DeepSeek、GLM、Kimi 和 Full 现已使用同一当前 20 样本 manifest，可直接作横向比较。

### 12:30—14:00：展示工程完整性

快速展示：

- FastAPI OpenAPI 页面；
- 前后端分离；
- SQLite 持久化 Adapter；
- `445 passed`；
- 实验 manifest、SHA-256、JSON 和 CSV；
- 无密钥提交原则。

### 14:00—15:00：主动说明边界并留出缓冲

建议说：

> 当前版本重点完成安全、可验证的漏洞发现与独立复核闭环。我们没有把单一静态信号伪装成已利用漏洞，也没有默认生成攻击载荷。符号剥离二进制已有成对实验；Windows Fuzz 已用 Job Object 强制资源和进程树限制，同时明确保留网络与文件系统隔离尚未实现的边界。

留出最后一分钟处理页面切换、老师提问或临时运行延迟。

## 7. 现场演示时必须强调的证据

不要只展示漂亮页面，要让老师看到以下“可验证链条”：

```text
输入样本
→ Task ID
→ Agent Route History
→ VulnerabilityCandidate
→ Evidence IDs
→ Verification Result
→ Final Report
```

每次展示漏洞时至少指出：

1. 漏洞来自哪个 Agent；
2. 关联了哪些 Evidence；
3. Verification 为什么确认、拒绝或保持不确定；
4. Report 如何引用同一结果；
5. 该结果是否执行过目标，安全边界是什么。

## 8. 当前必须诚实说明的验收风险

### 8.1 三个真实大模型与 Usage/Cost：已完成

DeepSeek V4 Flash、智谱 GLM-5.2 与 Kimi K2.6 已完成当前 20 个样本、60 次正式分类调用，三个接口均 20/20 成功并返回 usage。现场优先打开 `summary.md` 展示 Token、估算费用和 Evidence Coverage，再用 `run_manifest.json` 证明费率、币种、来源、运行起止时间与请求控制：

```text
artifacts/experiments/llm-comparison/
```

Kimi K2.6 的实测成绩可以进入 PPT，但必须同时说明：其接口只接受 `temperature=0.6`，当前账户的低 RPM 限制通过 21 秒最小间隔处理，因此 13.884 秒平均耗时包含节流等待；LLM-only 自然语言仍不构成 Evidence。

### 8.2 “2 个加壳样本 + 2 个混淆样本”：Part 6B 静态实测已完成

当前使用 4 个不同作者、不同程序身份的教育逆向挑战：加壳为 aj21h's Spaghetti（UPX + VM）和 Kowfsun's Custom packed crackme；混淆为 CrackNotMe's MCM 2.0 和 Desync's C# .NET Extended Obfuscation。它们均从 crackmes.one 的原始样本页取得，按网站非商业课程使用条款保留作者署名，并固定 SHA-256。

现场先打开 `artifacts/experiments/protected-readiness/readiness.json`：packing=2、obfuscation=2、`strict_requirement_met=true`。再打开 `artifacts/experiments/protected-benchmark/summary.md`，展示 4/4 静态信号、4/4 主链完成、4/4 Evidence 完整、3/4 可生成伪代码、1 个 UPX 文件级解包成功、目标执行 0 次。每个样本还有独立 JSON/HTML/PDF 报告。

答辩时按以下顺序展示：

1. 两个 manifest 中的来源、授权、作者、保护方式与 SHA-256；
2. readiness 的 2+2 严格门禁；
3. Part 6B 汇总表和任意一份 HTML/PDF；
4. UPX/radare2 的真实工具执行记录与降级信息；
5. Finding → Evidence → Verification → Report 主链；
6. `target_execution_count=0` 的安全边界。

这批挑战没有漏洞 Ground Truth，所以不能把保护特征检测、Crackme 求解或 UPX 解包写成“漏洞利用成功”，也不计算漏洞 Precision/Recall。这是当前与题目“漏洞挖掘与利用验证”表述之间仍需主动说明的边界。

重新验证与运行：

```powershell
.\.venv\Scripts\python.exe -m experiments.audit_protected_samples --manifest benchmarks\packed\manifest.json --manifest benchmarks\obfuscated\manifest.json --output-dir artifacts\experiments\protected-readiness --require-complete
.\.venv\Scripts\python.exe -m experiments.run_protected_benchmark --manifest benchmarks\packed\manifest.json --manifest benchmarks\obfuscated\manifest.json --output-dir artifacts\experiments\protected-benchmark --allow-transform
```

只有第一条返回 0 且 readiness 为 true，第二条才会进入真实静态分析和工具验证；全程不执行四个目标。

### 8.3 真实 ELF Benchmark/Demo：ELF-A 已完成

本机 WSL 损坏未被修改。系统使用官方 Zig 0.16.0 在 Windows 上交叉编译 6 个自研授权 C Fixture，生成 Symbol-Rich ET_EXEC、Stripped ET_EXEC、PIE/ET_DYN 三个 Profile，共 18 条只读分析记录。

现场打开 `artifacts/experiments/elf-benchmark/summary.md`：三个 Profile 均为 TP=3、FP=0、TN=3、FN=0，Evidence Coverage=1.0，目标执行 0 次。随后主动指出每个 Profile 只有 3 个正样本，95% Wilson 下界约 0.438，不能把本批 F1=1.0 外推成真实世界 100%。

复现：

```powershell
.\.venv\Scripts\python.exe -m experiments.run_elf_benchmark --manifest benchmarks\elf\manifest.json --output-dir artifacts\experiments\elf-benchmark --compiler tools\zig\zig-x86_64-windows-0.16.0\zig.exe
```

### 8.4 自动利用代码：当前采用安全受控验证

课程原文提到漏洞自动利用与利用代码。当前仓库遵循安全边界，没有默认实现自动攻击载荷、互联网扫描或第三方目标利用。答辩时应表述为“受控验证、Crash Evidence 和 PoC 接口”，不要宣称已经自动生成并执行通用 Exploit。

如果老师严格要求自动利用，应先与老师确认允许的教学靶标和验收口径，再只对本地自研靶标加入无危害的受控验证，不应临时对未知软件执行攻击。

## 9. 现场故障回退方案

### 前端无法启动

使用三个 CLI Demo 和已经生成的 JSON；同时打开 FastAPI `/docs` 展示接口。CLI 仍走正式 Orchestrator，不是伪造结果。

### 后端端口被占用

先检查：

```powershell
Get-NetTCPConnection -LocalPort 8000,5173 -ErrorAction SilentlyContinue
```

不要在答辩现场随意结束不认识的系统进程。提前关闭旧的 VulnAgent/Vite 进程并重新启动。

### 教室断网

不影响 Source、Binary、Fuzz 本地 Demo。LLM 对比展示已保存的 `metrics.json`、`labelled_results.json` 和 `run_manifest.json`，不要反复重试付费接口。

### GCC 不可用

提前生成并携带课程自研的 `binary-demo.exe`，使用 `--target` 分析；同时保留对应 C 源码和构建命令以便复核。

### 实时任务意外失败

先展示保存的 Demo JSON 和截屏录像，再根据错误信息解释。不要修改 JSON、隐藏失败或把旧结果说成刚刚生成。

## 10. 常见提问与建议回答

### “这是不是几个 Prompt 串起来？”

不是。系统使用统一 Task 状态、`AgentMessage`、Capability Registry、Supervisor 路由、最大步骤与重复路由限制；发现、验证和报告职责分离，所有阶段都留下事件和 Evidence。

### “为什么 LLM 和你们系统的 F1 都是 1？”

当前 20 个教学样本上分类已经饱和。VulnAgent 不应声称精度领先；可验证优势是 DeepSeek、GLM、Kimi 三个 LLM-only 的证据链覆盖率均为 0，而 VulnAgent 为 1.0，并且有独立 Verification 和可追溯报告。

### “二进制为什么是 UNCERTAIN？”

发现模块不能越权确认漏洞。符号剥离后，某些格式化函数共享 CRT 内部实现，现有公开静态事实不足以区分 `sprintf` 与安全的 `snprintf`。系统选择保持不确定，避免制造误报。

### “为什么没有自动 Exploit？”

当前课程版本把安全边界放在本地授权验证：可以生成候选、执行受控 Fuzz、记录 Crash 并复核，但不默认生成攻击载荷或攻击第三方系统。接口可以扩展，但执行必须经过授权和沙箱。

### “Fuzz 沙箱是否已经完全隔离？”

没有。Windows Job Object 已强制活动进程数、Job CPU 时间、进程/Job 内存和任务结束时回收进程树，且每次运行把内核限制写入 Evidence；它本身不能强制断网或限制文件系统访问，所以这两项明确显示为 unsupported。当前演示只运行仓库内自研、显式授权靶标，不能把这一层宣传成虚拟机隔离。

### “哪些部分是自研的？”

多 Agent 编排、结构化协议、统一漏洞与证据 Schema、独立复核、多来源融合、风险引导 Fuzz、实验框架和报告闭环是项目自研；第三方工具只位于 Adapter 边界后提供底层事实。

### “为什么不是课程建议的 Rust/Svelte？”

题目原文允许自选技术栈。项目使用 Python/FastAPI 实现安全分析与 Agent Runtime，使用 TypeScript/React 实现前端，把开发工作集中在可验证的多 Agent、Evidence、Verification 和实验创新上。

## 11. 最终彩排检查表

答辩前一天：

- [ ] 在实际演示电脑上完成一次全流程；
- [ ] 后端、前端、三个 CLI Demo 均可启动；
- [ ] `445 passed`、lint、build 结果已截图；
- [ ] Source/Binary/Fuzz 三份 HTML 与三份 PDF 均可离线打开；
- [ ] Source、Binary、Fuzz、LLM、ELF、Part 6B 六组实验产物可以打开；
- [ ] PPT 中每个数字都能对应到 `metrics.json`；
- [ ] 截屏录像能够离线播放，并包含声音或字幕；
- [ ] `.env` 和 API Key 未出现在录像、PPT、报告及压缩包；
- [ ] 已轮换曾经暴露的 API Key；
- [ ] 提交包已在另一目录解压并按安装文档试运行；
- [ ] 演示总时长不超过 14 分钟，至少留 1 分钟缓冲；
- [ ] 额外备份一份到 U 盘或学校允许的存储位置；
- [ ] 若提交渠道拦截 `.exe`，提前询问老师允许的提交方式，不绕过安全策略。

答辩当天：

- [ ] 提前到 N103 测试投影分辨率、字体和网络；
- [ ] 关闭通知、聊天软件弹窗和无关浏览器标签；
- [ ] 放大浏览器与终端字体；
- [ ] 提前启动服务并检查 `/api/health`；
- [ ] 不在投影中打开 `.env`；
- [ ] 先讲主线，再讲实现细节；
- [ ] 所有结果以现场界面或已保存实物为准，不背诵不一致的数字。

## 12. 最短演示口令

如果现场时间非常紧，只执行下面这条主线：

```text
创建 samples/source_demo 任务
→ 展示真实 Agent 路由
→ 打开一个 VulnerabilityCandidate
→ 追踪关联 Evidence
→ 展示 Verification 将 Candidate 变为 Confirmed
→ 打开最终 Report
→ 用 metrics.json 展示 Guided Fuzz 和 LLM-only 对照
→ 主动说明 Binary UNCERTAIN 与安全边界
```

这条主线能够同时证明系统不是单次 LLM 调用、不是静态页面、不是第三方扫描器换皮，并突出 VulnAgent 最有价值的 Evidence First 和 Independent Verification 设计。
