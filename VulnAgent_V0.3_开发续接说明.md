# VulnAgent V0.3 开发续接说明

> 用途：供新的开发者或新的 GPT/Codex 对话快速恢复上下文。接手者应先完整阅读仓库根目录的 `AGENTS.md`，再阅读本文；项目要求原文位于 `2026网络空间安全课程设计-new.md`，现状/缺口原文位于 `VulnAgent_V0.3_当前进度_功能缺口与创新性推进.md`。
>
> 状态截至：2026 年 9 月 11 日。

## 1. 项目目标与不可破坏的边界

VulnAgent 是课程设计题目 1 的自研多智能体软件漏洞挖掘系统。目标是将程序理解、源码/二进制静态分析、受控模糊测试、独立复核、证据链和自动报告串成可追踪流水线，而不是简单包装第三方扫描器或串行调用若干 Prompt。

继续开发时必须遵守以下边界：

- `Task`、`AgentMessage`、`VulnerabilityCandidate`、`Evidence` 是冻结公共协议，不能随意修改。
- 发现 Agent 只能产生候选；只有 Verification 层可以写入 `CONFIRMED` 或 `REJECTED`。
- 每个正式漏洞结论必须关联结构化 Evidence；模型自然语言不能单独证明漏洞。
- 所有模型调用必须经过 `src/vulnagent/llm/` 的统一抽象层。
- Fuzz 只面向本地课程样本、授权目标或沙箱目标；不扫描公网，不生成攻击命令。
- 当前子进程执行策略中的 `network_enabled=False` 只是策略声明，尚未形成操作系统级网络隔离。文档和实验记录不得把它描述为已强制断网。
- 不提交真实 `.env`、API Key、Token 或数据库密码。

## 2. 本轮已经完成的工作

### 2.1 Codex 插件与 Skills

已安装并启用 GitHub 插件，用于后续仓库协作。已安装以下本地 Skills：

- `jupyter-notebook`：后续把实验结果整理成可复用分析 Notebook。
- `playwright`：真实浏览器端到端测试与演示流程回归。
- `security-threat-model`：后续单独开展仓库级威胁建模时使用。

本轮还实际使用了插件管理、Skill 安装、OpenAI/Codex 文档和应用内浏览器能力。新会话如未立即显示新安装的 Skill，重启 Codex 会话后再检查。

### 2.2 二进制分析正式接入主链

已将二进制逻辑风险分析与混淆检测从孤立模块接入统一能力注册和多智能体流水线：

- `CapabilityBundle` 新增 binary logic / obfuscation 能力。
- Tool Registry 注册 `binary.logic`、`binary.obfuscation`。
- Bootstrap 支持真实实现与 Mock 实现的注入。
- Planner 可规划二进制分析能力。
- `BinaryAnalysisAgent` 并发执行逻辑风险与混淆分析，统一写入 `TOOL_RESULT` Evidence 和任务元数据。
- 二进制候选仍进入独立 Verification，不越权确认漏洞。

### 2.3 自研 Benchmark 与可复现实验框架

新增三类自研实验资产：

- 源码 Benchmark：`benchmarks/source/` 下 12 个 Python 样本，包含 6 个漏洞样本与 6 个安全反例，覆盖 CWE-22、CWE-78、CWE-89、CWE-95、CWE-502。
- 二进制 Benchmark：`benchmarks/binary/case-001..006/app.c`，包含 `strcpy`、`system`、`sprintf` 风险样本和 `memcpy`、`puts`、`snprintf` 安全反例。
- Fuzz Benchmark：`benchmarks/fuzz/manifest.json`，用于固定预算的引导/非引导配对实验。

新增脚本：

- `experiments/run_metrics.py`：统一计算 Precision、Recall、F1、FPR、Evidence Coverage、Wilson 区间和运行指标，并以 JSON/JSONL 输出。
- `experiments/run_source_ablation.py`：比较 verification off、verification on、full system 三组。
- `experiments/run_binary_benchmark.py`：对相同教学 C 样本成对编译 Symbol-Rich/Stripped 两组，只做静态分析，不执行目标。
- `experiments/run_fuzz_ablation.py`：固定相同执行预算，对比风险引导与普通变异。
- `experiments/run_llm_comparison.py`：真实模型对比入口；至少配置两个供应商才运行，结果区分 LLM-only 与完整系统，且不会写出密钥。

当前实验结果：

| 实验 | 关键结果 | 诚实性说明 |
|---|---|---|
| 源码三组消融 | 三组 Precision/Recall/F1 均为 1.0；Evidence Coverage 1.0；verification off 的 confirmed=0，on/full 的 confirmed=6 | 样本量仅 12，Wilson 下界约 0.610，不能外推为工业级准确率 |
| 二进制 Symbol-Rich | Precision/Recall/F1=1.0，FPR=0 | 精确符号策略命中 `strcpy`/`system`/`sprintf`，不再把 `snprintf` 的 CRT 内部实现误报；3 个候选均为 `UNCERTAIN` |
| 二进制 Stripped | Precision=1.0，Recall≈0.667，F1=0.8，FPR=0 | 去符号后仍命中 `strcpy`/`system`，但缺乏区分 `sprintf` 与 `snprintf` 的静态事实，保守漏报 1 项 |
| Fuzz 配对消融 | 两组总预算均为 80 次；风险引导 10/10 命中崩溃路径，普通变异 0/10；覆盖代理 0.25 vs 0.125 | 引导组有 10 次崩溃运行，但全局去重后只有 1 个独立崩溃指纹 |

实验产物默认写入 `artifacts/experiments/`，该目录已加入 `.gitignore`。

### 2.4 风险引导的受控 Fuzz

新增 `src/vulnagent/fuzz/guidance.py`，根据已有结构化 Finding 生成有限、确定性、无攻击语义的标记和解析器边界输入。`FuzzAgent` 从候选中提取受限风险提示；Engine 在固定总预算内混合引导种子和普通种子，并记录：

- seed strategy；
- execution trace；
- coverage proxy；
- crash fingerprint；
- Finding 与 Evidence 的关联。

课程示例目标仅在接收到 `VULNAGENT_CODE_MARKER` 时触发受控崩溃路径，不包含真实利用载荷。

### 2.5 SQLite 断点恢复

新增：

- `src/vulnagent/core/context_store.py`
- `src/vulnagent/storage/sqlite.py`

SQLite Repository 统一持久化 Task、Evidence 和完整运行上下文 JSON 快照，提供 Evidence 语义去重和线程锁。Orchestrator 会保存已完成/失败上下文；Bootstrap 在 `STORAGE_BACKEND=sqlite` 时注入共享 Repository。已经覆盖重启后恢复 Task、Evidence、Findings 和 Report 的测试。

相关配置：

```dotenv
STORAGE_BACKEND=memory
SQLITE_PATH=artifacts/vulnagent.db
```

### 2.6 真实 LLM Adapter 与双模型对比入口

新增 `src/vulnagent/llm/openai_compatible.py`：

- `OpenAICompatibleLLM`
- `DeepSeekAdapter`
- `GLMAdapter`
- `LLMProviderError`

它们使用 OpenAI-compatible Chat Completions 协议、Bearer 鉴权、超时和脱敏错误信息。`LLMRouter.from_settings` 根据配置显式选择供应商；缺少 Key 时清晰失败，不静默假装真实模型结果。Adapter 已支持受约束的 `thinking` 开关，分类与 Planner 短 JSON 请求显式关闭深度思考，避免推理内容占满输出预算。

Planner 已注入统一 `BaseLLM`：它只发送目标类型、语言、文件格式等最小元数据，不发送本地绝对路径；模型只提供公开安全建议，Supervisor 的确定性路由仍是最终权威，模型失败会回退。

默认配置依据当前官方文档：

```dotenv
DEEPSEEK_BASE_URL=https://api.deepseek.com
DEEPSEEK_MODEL=deepseek-v4-flash
GLM_BASE_URL=https://open.bigmodel.cn/api/paas/v4
GLM_MODEL=glm-5.2
```

2026-09-11 已使用本地 `.env` 中的 DeepSeek 与 GLM 配置完成真实对比；密钥没有写入任何实验产物。共完成 24 次真实分类调用，两家均 12/12 成功。复现命令如下，但再次运行会产生 API 费用：

```powershell
.\.venv\Scripts\python.exe -m experiments.run_llm_comparison --manifest benchmarks\manifest.json --providers deepseek glm --output-dir artifacts\experiments\llm-comparison
```

真实结果：DeepSeek、GLM 与 VulnAgent Full 的 Precision/Recall/F1 均为 1.0；DeepSeek/GLM 的 Evidence Chain Coverage 均为 0、Confirmed Findings 均为 0，VulnAgent Full 分别为 1.0 和 6。平均耗时分别为 3.040 秒、3.641 秒和 0.060 秒。样本只有 6 个阳性和 6 个阴性，Wilson 95% 下界约为 0.610，不能宣称对真实世界具有同等检测率。

### 2.7 演示脚本

- `scripts/demo_binary_v03.py`：在本地编译示例 PE 后走正式二进制流水线，目标不会被执行。
- `scripts/demo_fuzz_v03.py`：走源码分析 → 风险引导 Fuzz → Verification → Reviewer → Report 主链。

已实际运行并生成：

- `artifacts/demos/binary-v03.json`
- `artifacts/demos/fuzz-v03.json`

二进制 Demo 完成并产生 1 个 `UNCERTAIN` finding；Fuzz Demo 完成，8 次固定预算中 4 次引导、4 次普通，产生 1 条 crash evidence 和 2 个经复核的 confirmed findings。

### 2.8 文档与安全口径

新增或更新：

- `docs/04_evaluation/reproducible_evaluation.md`
- `benchmarks/README.md`
- `experiments/README.md`
- `README.md`
- `.env.example`
- `VulnAgent_V0.3_当前进度_功能缺口与创新性推进.md`

所有文档已统一更正：`network_enabled=False` 当前不是 OS 级强制断网；不再将声明式策略写成真实安全隔离。

### 2.9 Windows 并发原子写可靠性

全量测试曾复现 `BinaryArtifactStore` 在 Windows 上并发写入时偶发 `PermissionError`。`src/vulnagent/analyzers/binary/reverse/artifacts.py` 现已对 `os.replace` 的短暂访问冲突实施有限指数退避重试；重试有严格上限，最终失败仍向调用者报告，不会无限等待或吞掉错误。新增故障注入测试后，并发用例连续运行 30 次无失败。

### 2.10 二进制符号可观测性消融

`BinaryAnalysisAgent` 的危险符号识别已从任意子串匹配改为精确 Token 与常见修饰名归一化。它会识别 `__imp_strcpy`、`ucrt_sprintf.c` 等明确符号，但不会把安全的 `snprintf`、`strcpy_s`、普通单词 `systematic`，或同时服务 `sprintf`/`snprintf` 的 `__stdio_common_vsprintf` 当成独立漏洞信号。

Binary Benchmark 对相同 6 个源码进行成对编译，唯一变量为是否使用 `-s`。实验不会读取 `benchmark_source` 帮检测器猜答案：

- Symbol-Rich：3 TP、3 TN、0 FP、0 FN，F1=1.0；
- Stripped：2 TP、3 TN、0 FP、1 FN，F1=0.8；
- 两组 Evidence Coverage 均为 1.0，目标均未执行；
- 所有实际产生的风险候选仍是 `UNCERTAIN`。

这个结果既修掉了原有 `snprintf` 误报，也量化了去符号对召回率的真实影响。下一步若要恢复 Stripped `sprintf` 召回率，必须加入经过验证的调用点/参数上下文，不能重新退回子串猜测。

## 3. 已完成的验证

本轮最终门禁结果：

- Python 全量测试：`396 passed`，仅 1 条 Starlette/AnyIO 弃用警告。
- BinaryArtifactStore 12 线程并发用例连续 30 次通过，瞬时 `PermissionError` 故障注入测试通过。
- 前端依赖：`npm ci` 成功，85 个包，0 个已报告漏洞。
- 前端：`npm run lint`、`npm run build` 均通过。
- 三类源码/二进制/Fuzz 实验均可完成。
- 二进制和风险引导 Fuzz 正式 Demo 在最终修改后再次运行成功。
- 源码 UI Demo 走真实后端完成：4 个 confirmed findings、20 条 Evidence、复核置信度均值 86%。
- 二进制 UI Demo 走真实后端完成：1 个 finding、4 条 Evidence、复核结论 `UNCERTAIN`；前端没有将其误标为 `CONFIRMED`。
- 新建干净浏览器标签完成 Dashboard、Evidence、Vulnerabilities、Report、API Console 巡检；控制台 0 error、0 warning。
- LLM Adapter 契约测试通过；DeepSeek V4 Flash 与 GLM-5.2 的 24 次真实分类调用全部成功，真实结果与运行清单位于 `artifacts/experiments/llm-comparison/`，没有记录密钥。
- Binary Symbol-Rich/Stripped 成对实验在最终代码上重新生成，结果分别为 F1=1.0 与 F1=0.8，两个 Profile 的 FPR 均为 0。

## 4. 本轮前端真实性收尾

应用内浏览器端到端检查发现 Dashboard 存在一组与真实任务无关的视觉占位数字和技术名词，例如 `84.6%`、`1,420 exec/s`、`98%`、`x86_64`、`AFL++`、`ASAN`。这些会让课程验收误以为系统在伪造遥测。

已完成的修正：

- Dashboard 从真实 `route_history` 计算各流水线阶段是否到达。
- 从真实 Coverage、Runtime Trace、Crash Log、Verification Result、Evidence 类型计算指标。
- 源码和二进制 Benchmark 卡片改为仓库中实际存在/可生成的课程样本。
- 删除界面中未经实现的 AFL++、libFuzzer、ASAN、SIGSEGV 等硬编码能力声明。
- API Console 使用实际 FastAPI `8000` 端口；Footer 不再虚构 Git 分支或“工作区干净”状态。
- Finding 详情按实际关联 Evidence 和实际 Verification 状态展示；二进制 `UNCERTAIN` 已通过真实 UI 验证。
- Coverage/Fuzz 未运行时明确显示 `N/A` 或 `0`，不再展示伪造吞吐率和覆盖率。
- 修正 Evidence 页翻译键、React 列表 key 告警和异步 Findings 初次载入时未自动选中问题。
- 应用内浏览器最终检查没有发现旧硬编码遥测，且控制台无 error/warning。

当前没有尚未收尾的本轮代码项。课程要求的真实双模型对比已经完成，相关限制和可复现数据已经写入评测文档。

## 5. 推荐后续开发顺序

完成当前收尾后，建议按以下顺序推进：

1. **恢复 Stripped 格式化函数召回率**：加入经过测试的调用点/参数上下文，在保持 `snprintf` 零误报的前提下识别 `sprintf`；继续使用 Symbol-Rich/Stripped 单变量对比。
2. **增加二进制平台覆盖**：当前 Windows 环境优先覆盖 PE；若有 Linux/WSL，再补 ELF 样本与相同 manifest 格式。
3. **强化 Fuzz 隔离**：使用 Windows Job Object、容器或 WSL namespace 实现真正的资源/网络边界，再更新安全声明和实验。
4. **扩大 Benchmark 与交叉验证**：每个 CWE 增加不同写法、跨函数数据流和困难安全反例，避免针对当前规则过拟合。
5. **生成最终课程实物包**：一键 Demo、固定实验 JSON、HTML/Markdown 报告、运行说明和演示脚本。
6. **最后再制作 PPTX**：用户本轮明确暂不制作；PPT 应只引用已经可复现的数据和真实截图。

## 6. 新会话最短接手提示词

可将下面内容直接发给新的 GPT/Codex：

```text
请先完整阅读仓库根目录 AGENTS.md、项目要求文档、VulnAgent_V0.3_当前进度_功能缺口与创新性推进.md，以及 VulnAgent_V0.3_开发续接说明.md。严格遵守冻结 Schema、Evidence First、Verification-only confirmation 和本地授权 Fuzz 边界。先检查工作区现状并运行最小验证，不要重做已完成模块；从“开发续接说明”的当前工作和推荐后续顺序继续。不要制作 PPTX，除非我再次明确要求。
```

## 7. 常用复现命令

```powershell
# Python 全量测试
.\.venv\Scripts\python.exe -m pytest --basetemp .\.pytest-tmp -q

# 前端
npm run lint
npm run build

# 三类实验
.\.venv\Scripts\python.exe -m experiments.run_source_ablation --manifest benchmarks\manifest.json --output-dir artifacts\experiments\source-ablation
.\.venv\Scripts\python.exe -m experiments.run_binary_benchmark --manifest benchmarks\binary\manifest.json --output-dir artifacts\experiments\binary-benchmark
.\.venv\Scripts\python.exe -m experiments.run_fuzz_ablation --manifest benchmarks\fuzz\manifest.json --output-dir artifacts\experiments\fuzz-ablation --trials 10 --mutation-count 8

# 正式 Demo
.\.venv\Scripts\python.exe scripts\demo_binary_v03.py
.\.venv\Scripts\python.exe scripts\demo_fuzz_v03.py

# 配置至少两个真实供应商 Key 后再运行
.\.venv\Scripts\python.exe -m experiments.run_llm_comparison --manifest benchmarks\manifest.json --providers deepseek glm --output-dir artifacts\experiments\llm-comparison
```
