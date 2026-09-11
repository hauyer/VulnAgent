# VulnAgent V0.3 当前进度、功能缺口与创新性推进说明

> 2026-09-11 个人续作更新：GAP-01 已完成，Binary Reverse、Logic、Obfuscation 已通过正式 Agent Runtime、Evidence、Verification 和 Report 串联；GAP-02 已加入 12 个 Source、6 个 Binary 与 1 个 Fuzz 场景清单；GAP-03 已落地 Verification ON/OFF、Agent-Guided/Traditional Fuzz、Binary Symbol-Rich/Stripped 三组可复现实验，并完成 DeepSeek V4 Flash、GLM-5.2 与 VulnAgent Full 的真实 12 样本对比；GAP-04 已加入可选 SQLite Repository Adapter；GAP-05 已固定 Source、Binary、Fuzz 三个正式 Demo。Binary 检测已改用精确符号策略，消除 `snprintf` 子串误报，同时诚实量化 Stripped 样本的信息损失。真实 LLM 对比的 24 次调用全部成功：三种方法分类 F1 均为 1.0，但两个 LLM-only 基线的证据链覆盖率为 0，VulnAgent Full 为 1.0。当前实测数据及限制见 `docs/04_evaluation/reproducible_evaluation.md`。PPTX 按当前个人开发安排暂缓。

> 项目：VulnAgent —— 基于大模型多智能体的软件漏洞挖掘与验证系统  
> 当前开发分支：`develop`  
> 当前阶段：V0.3 First Real Vulnerability Analysis Loop / 系统集成阶段  
> 文档用途：团队进度检查、后续任务分配、系统联调、课程设计创新性落实  
> 更新时间：2026 年 9 月 10 日

---

# 1. 当前总体状态

VulnAgent 已完成从 **V0.2 Multi-Agent Architecture Foundation** 向 **V0.3 真实漏洞分析闭环** 的主要过渡。

当前 `develop` 最新版本已经不再是以 Mock 为主的纯架构骨架，而是形成了：

```text
React / Vite Frontend
        ↓
      /api
        ↓
     FastAPI
        ↓
Core Orchestrator
        ↓
AgentRuntime / Supervisor / AgentRouter
        ↓
CapabilityBundle / ToolRegistry
        ↓
┌─────────────────────────────────────────────┐
│ Source Parser / Source Audit                │
│ Binary Analysis / Controlled Fuzz           │
│ Independent Verification / Reviewer         │
│ Evidence / Structured Report                │
└─────────────────────────────────────────────┘
```

当前正式业务链保持：

```text
Task
 ↓
Planner / Supervisor
 ↓
Discovery Agent
 ↓
VulnerabilityCandidate
 ↓
Evidence
 ↓
Verification
 ↓
Reviewer
 ↓
Report
 ↓
Frontend
```

其中，源码分析链已经基本实现真实能力：

```text
SourceProjectParser
        ↓
PythonSourceAuditor
        ↓
VulnerabilityCandidate
        ↓
Evidence
        ↓
EvidenceVerifier
        ↓
ReviewerAgent
        ↓
StructuredReportGenerator
        ↓
FastAPI
        ↓
React Frontend
```

当前 `v03-source` Profile 已经实际注入：

```python
SourceProjectParser()
PythonSourceAuditor()
StaticBinaryReverseAnalyzer()
ControlledFuzzEngine()
EvidenceVerifier()
StructuredReportGenerator()
```

因此 V0.3 已经具备“真实分析系统”的基本形态，而不是仅依靠 Mock Agent 演示多智能体流程。

---

# 2. 当前已经完成的核心工程基础

## 2.1 Core / Agent Runtime 架构

当前已经基本完成：

- `Task` 生命周期管理；
- `Orchestrator` 作为系统级 Task 生命周期唯一拥有者；
- `AgentRuntime` 负责单次多 Agent 图执行；
- LangGraph 风格的 Agent Runtime；
- `PlannerAgent`；
- `Supervisor`；
- `AgentRouter`；
- `RuntimePolicy`；
- `AgentRegistry`；
- `ToolRegistry`；
- `CapabilityBundle`；
- Composition Root：`bootstrap.py`；
- `AnalysisContext` 与 `RuntimeState` 职责分离；
- `AgentMessage`；
- `DomainEvent`；
- Runtime Trace；
- API 可查询的事件和运行轨迹；
- Mock / Real Profile 切换。

当前默认运行约束为：

```text
MAX_AGENT_STEPS=15
MAX_ROUTE_REPEATS=2
MAX_ANALYSIS_RETRIES=1
```

已经建立：

- 最大 Agent 步数限制；
- 重复路由限制；
- analysis retry 限制；
- 非法路由安全回退；
- Runtime 异常保护；
- Agent 运行失败后的有界终止机制。

这部分已经基本达到 V0.2 Architecture Freeze 的目标。

---

# 3. P1 Core / Contracts / Agent Runtime 当前完成情况

## 3.1 已完成

P1 当前已完成或基本完成：

- Core Task 生命周期；
- Orchestrator；
- AgentRuntime；
- Supervisor；
- AgentRouter；
- RuntimePolicy；
- ToolRegistry；
- AgentRegistry；
- BaseAgent 体系；
- CapabilityBundle；
- Bootstrap / Dependency Injection；
- Mock / V0.3 Profile；
- Agent Route Trace；
- Domain Event；
- API 与 Runtime 对接；
- 架构依赖守卫；
- Runtime 边界测试；
- 非法 Route 测试；
- 重复 Route 测试；
- 最大 Agent Step 测试；
- Analysis Retry 测试；
- Runtime 异常回退测试。

## 3.2 当前缺失

P1 后续不应该继续大规模重构 Core，而应主要负责：

- 全系统集成；
- Binary Logic 接入 Runtime；
- Source / Binary / Fuzz 联合运行；
- Runtime 和 API 联调；
- Profile 管理完善；
- Provider Adapter 联调；
- Persistence 后端接入；
- Release Candidate 稳定性检查。

### 当前原则

从 V0.3 开始：

> Core 进入“冻结 + 集成维护”阶段，而不是继续扩张阶段。

禁止为了增加所谓创新性重新大规模修改：

```text
Orchestrator
AgentRuntime
Contracts
AnalysisContext
RuntimeState
```

创新能力应尽量在已有 Protocol / Adapter / Agent 插槽中实现。

---

# 4. P2 Source Parser 当前完成情况

## 4.1 已完成

当前已经实现真实 Source Parser。

主要包括：

- 本地项目导入；
- 单文件项目支持；
- ZIP 项目导入；
- Git 项目导入基础能力；
- Zip Slip 防护；
- 文件数量和大小限制；
- 忽略依赖目录；
- 忽略虚拟环境；
- 忽略构建目录；
- 多语言识别；
- Python AST；
- 文件索引；
- Class / Function / Method 符号；
- 参数信息；
- Decorator；
- Return Annotation；
- import 关系；
- import 位置；
- 基础调用图；
- 跨模块调用目标 best-effort 解析；
- 项目入口点识别；
- 解析错误记录；
- 大文件跳过；
- Unsupported Language 明示；
- SourceAnalysisResult 标准输出。

当前 Parser 已经能够支持：

```text
真实 Python 项目
      ↓
SourceAnalysisResult
      ↓
P3 Source Audit
```

P3 不需要读取 P2 内部 Parser 对象即可完成后续分析。

## 4.2 当前缺失

当前主要限制包括：

- Python 之外语言主要停留在语言识别；
- C / C++ AST 尚不完善；
- Java AST 尚不完善；
- Go / Rust 等语言暂不具备深层语义结构；
- 跨函数数据流能力有限；
- 动态调用无法完整解析；
- 反射 / Monkey Patch 无法可靠解析；
- 高级类型推断未完成；
- 全程序调用图仍属于 best-effort。

## 4.3 后续建议

V0.3 不建议立即追求全语言 AST。

优先保证：

```text
Python Parser
      ↓
Python Audit
```

稳定运行。

V0.4 再考虑扩展：

```text
C/C++
Java
```

---

# 5. P3 Source Audit 当前完成情况

## 5.1 已完成

目前已有真实：

```text
PythonSourceAuditor
```

支持的基础漏洞类型包括：

- Command Injection；
- SQL Injection；
- Path Traversal；
- Unsafe Deserialization；
- Dynamic Code Execution；
- Dangerous API；
- Source / Sink；
- Import Alias；
- 简单安全用法过滤；
- 函数内轻量污点传播。

输出统一：

```text
VulnerabilityCandidate
```

发现模块仅产生：

```text
CANDIDATE
```

不会直接越权产生：

```text
CONFIRMED
REJECTED
```

同时保留：

- Rule；
- CWE；
- Location；
- Taint Path；
- Metadata；
- Evidence 关联信息。

## 5.2 当前缺失

仍缺少：

- 跨函数污点分析；
- 跨文件复杂数据流；
- Path-Sensitive Analysis；
- Context-Sensitive Analysis；
- Sanitizer 精确建模；
- Framework-aware 分析；
- Flask / Django / FastAPI 路由语义分析；
- C/C++ Source Audit；
- Java Source Audit；
- 大规模规则库；
- Semgrep 与自研规则融合的系统化实验。

## 5.3 创新性推进方向

P3 后续不要简单扩充“危险函数数量”。

优先考虑：

```text
Rule Signal
    +
AST Signal
    +
Data Flow Signal
    +
LLM Semantic Signal
    ↓
Candidate Fusion
```

形成：

> 多来源源码漏洞候选融合机制。

这比增加几十条简单正则规则更有课程创新价值。

---

# 6. P4 Binary Reverse 当前完成情况

## 6.1 已完成

Binary Reverse 已经实现：

- PE 基础解析；
- ELF 基础解析；
- Architecture；
- Bitness；
- Sections；
- Entry Point；
- Strings；
- Imports；
- Exports；
- Symbols；
- 基础函数信息；
- 基础 CFG；
- 高熵 Section 信号；
- Packing / Obfuscation 基础启发式；
- UPX Adapter；
- radare2 Adapter；
- Tool Timeout；
- Tool Error；
- Artifact 输出；
- BinaryAnalysisResult；
- 不执行未知目标的静态安全边界。

## 6.2 当前缺失

当前最大问题不是“没有代码”，而是：

> P4 的分析能力还没有完全成为成熟的 Binary 漏洞发现闭环。

仍缺少：

- radare2 真实环境系统验收；
- UPX 真实工具系统验收；
- 更完整函数恢复；
- 更完整 CFG；
- Call Graph；
- 反编译结果统一化；
- 二进制危险函数 / Sink 判断；
- Binary Candidate 标准化；
- Binary → Verification 完整主链验证；
- 多种真实授权 Binary Sample。

---

# 7. P5 Binary Obfuscation / Logic 当前完成情况

## 7.1 已完成

当前已经存在 Binary Logic 真实分析模块。

主要目标包括：

- Authentication Logic；
- Cryptographic Logic；
- License / Registration Logic；
- Network Input Logic；
- Memory Operation Logic；
- Obfuscation 信号；
- 高价值函数定位。

P5 已经具备实际实现代码，不是纯目录占位。

## 7.2 当前最重要缺失

P5 是当前系统中最明显的“模块已开发，但主链集成不足”的部分。

当前 ToolRegistry 主要能力包括：

```text
source.parse
source.audit
binary.inspect
fuzz.execute
verification.verify
report.generate
```

P5 尚未形成类似：

```text
binary.logic
binary.obfuscation
```

的正式能力注册和 Agent Runtime 路由。

因此当前实际链路更接近：

```text
Binary
 ↓
P4 Static Binary Analysis
 ↓
Verification / Report
```

理想链路应该是：

```text
Binary
 ↓
P4 Reverse
 ↓
BinaryAnalysisResult
 ↓
P5 Obfuscation / Logic
 ↓
High-value Region / Candidate
 ↓
Evidence
 ↓
P7 Verification
 ↓
Report
```

## 7.3 下一阶段重点

P5 是下一轮的重要集成任务。

推荐新增：

```text
binary.logic
```

或在不破坏 Contracts 的前提下建立 Binary Logic Agent。

重点体现：

> 二进制基础事实与高层安全语义分离。

这本身也是系统工程创新的一部分。

---

# 8. P6 Dynamic / Fuzz 当前完成情况

## 8.1 已完成

当前 Fuzz 模块已经实现：

- Seed Corpus；
- Mutation；
- Controlled Executor；
- Process-level Sandbox；
- Timeout；
- Working Directory；
- Crash 捕获；
- Coverage 基础指标；
- Runtime Trace；
- Evidence；
- 授权检查；
- Planner Fuzz Opt-in；
- `fuzz_authorized=true`；
- `dynamic_validation=true`；
- 有界运行时间；
- 默认关闭网络；
- Crash Evidence。

当前已经可以形成：

```text
Seed
 ↓
Mutation
 ↓
Controlled Execution
 ↓
Crash / Coverage
 ↓
Evidence
 ↓
Verification
```

## 8.2 当前缺失

仍然缺少：

- VM 级隔离；
- Container 强隔离；
- CPU / Memory / PID 完整资源控制；
- AFL++；
- libFuzzer；
- honggfuzz；
- Coverage Instrumentation 深度接入；
- Corpus Minimization；
- Crash Minimization；
- Crash Clustering；
- Sanitizer 系统集成；
- Static → Fuzz Seed Generation；
- Agent-guided Mutation。

## 8.3 创新性优先方向

不要单纯变成：

```text
LLM
 ↓
调用 AFL++
```

这不具备足够自研价值。

推荐重点实现：

```text
Static Analysis
      ↓
High-risk Function / Input
      ↓
Agent Planning
      ↓
Seed Prioritization
      ↓
Mutation Strategy Selection
      ↓
Fuzz
      ↓
Crash Evidence
      ↓
Verification
```

形成真正的：

> Agent-Guided Fuzzing。

这是 VulnAgent 后续最值得强化的创新点之一。

---

# 9. P7 Verification / Reviewer 当前完成情况

## 9.1 已完成

当前 Verification 已经是系统中完成度较高的模块。

已有：

- `EvidenceVerifier`；
- Candidate Duplicate Canonicalization；
- Evidence Fusion；
- Location 检查；
- Evidence Reliability；
- Confidence 计算；
- CONFIRMED；
- REJECTED；
- UNCERTAIN；
- Verification rationale；
- Verification Evidence；
- Reviewer 二次检查。

当前 CONFIRMED 已经不是简单依赖模型输出。

基本规则包括：

```text
有效位置
+
至少两个相互独立的 Probative Evidence
+
Reliability Threshold
=
可进入 CONFIRMED
```

模型生成的解释文本：

```text
MODEL_REASONING_SUMMARY
```

不能单独提高漏洞确认可信度。

辅助 Evidence，例如：

```text
Runtime Trace
Tool Result
Coverage
Fuzz Input
```

也不能单独完成漏洞确认。

## 9.2 创新价值

这一模块已经能够体现 VulnAgent 一个非常明确的创新点：

> Independent Evidence-driven Verification

区别于：

```text
LLM 发现漏洞
        ↓
LLM 自己说自己发现得对
```

VulnAgent 采用：

```text
Discovery
    ↓
Candidate
    ↓
Independent Verification
    ↓
Reviewer
```

这对减少 LLM Hallucination 和漏洞误报非常重要。

## 9.3 当前缺失

后续可以继续加入：

- Source-specific Verification；
- Binary-specific Verification；
- Crash Reproduction；
- Symbolic / Constraint Verification；
- 二次工具复核；
- CVSS 语义；
- Evidence Contradiction Detection；
- 多 Agent Verification Voting。

---

# 10. P8 Platform / API / Frontend 当前完成情况

## 10.1 已完成

目前已建立 React + TypeScript + Vite 前端。

已有：

- Dashboard；
- Task 页面；
- Vulnerability 页面；
- Evidence 展示；
- Report 展示；
- Agent 运行状态；
- Event；
- Trace；
- API Client；
- i18n；
- 基础视觉设计；
- FastAPI 对接。

当前主要 API 包括：

```text
GET  /api/health
GET  /api/tasks
POST /api/tasks

GET  /api/tasks/{task_id}
POST /api/tasks/{task_id}/run

GET /api/tasks/{task_id}/events
GET /api/tasks/{task_id}/trace

GET /api/tasks/{task_id}/findings
GET /api/tasks/{task_id}/evidence
GET /api/tasks/{task_id}/verifications
GET /api/tasks/{task_id}/report
```

同时已经清理原先错误形成的 TypeScript 第二业务后端。

当前原则已经恢复为：

```text
React
 ↓
FastAPI
 ↓
Python Core
```

而不是：

```text
React
 ↓
TypeScript Orchestrator

Python
 ↓
另一套 Orchestrator
```

## 10.2 当前缺失

主要缺少：

- 所有页面真实数据完全验收；
- Error Boundary；
- Loading / Retry；
- 实时运行进度；
- WebSocket / SSE；
- Agent Graph 动态显示；
- Evidence Graph 交互；
- Task 历史管理；
- Report Export；
- 大规模任务列表；
- API Schema 自动同步；
- 更完整响应式界面。

## 10.3 当前优先级

P8 接下来不应优先继续增加页面数量。

优先完成：

```text
同一个真实 Task
      ↓
Dashboard
      ↓
Agent Trace
      ↓
Finding
      ↓
Evidence
      ↓
Verification
      ↓
Report
```

保证全部数据一致。

---

# 11. P9 Evidence / Report / Benchmark 当前完成情况

## 11.1 Evidence 已完成部分

当前 Evidence 体系已经具备：

- Evidence Store；
- Task Evidence；
- Finding Evidence；
- Verification Evidence；
- Runtime Trace Evidence；
- Evidence ID；
- Evidence Relation；
- Evidence Timeline 基础能力；
- Report Evidence 引用。

## 11.2 Report 已完成部分

Structured Report 已经包含：

- Task Summary；
- Findings；
- CWE 分类；
- Severity；
- Evidence；
- Verification Reasoning；
- Risk Summary；
- Remediation；
- Evidence Timeline；
- Confidence；
- Rejected / Confirmed / Uncertain 状态。

报告生成遵守：

> Report 只消费结构化结果，不自行重新判断漏洞。

这是正确的 Evidence First 设计。

## 11.3 Experiment 已完成部分

当前已经存在：

```text
experiments/
├── README.md
└── run_metrics.py
```

已经开始形成结构化实验能力。

## 11.4 当前最大缺失：Benchmark

目前：

```text
benchmarks/
├── README.md
└── .gitkeep
```

Benchmark 仍然非常薄弱。

这已经成为当前项目创新性证明最大的短板之一。

---

# 12. 当前功能完整度总结

| 模块 | 当前完成度 | 状态 |
|---|---:|---|
| Core / Runtime | 90%～95% | 🟢 |
| Source Parser | ≈90% | 🟢 |
| Source Audit | 85%～90% | 🟢 |
| Binary Reverse | 75%～80% | 🟡 |
| Binary Logic | 65%～70% | 🟡 |
| Dynamic / Fuzz | 75%～80% | 🟡 |
| Verification | ≈90% | 🟢 |
| Platform / Frontend | 80%～85% | 🟢 |
| Evidence / Report | ≈80% | 🟢 |
| Benchmark / Experiment | 45%～55% | 🟠 |
| Persistence | ≈20% | 🔴 |
| 最终端到端验收 | ≈60% | 🟡 |

整个项目综合进度大约：

> **75%～80%**

其中最关键的：

> **真实 Python Source Vulnerability Analysis Loop 已达到约 90% 完成度。**

---

# 13. 当前系统最重要的功能缺口

从课程设计最终验收角度，目前最重要的缺口不是继续新增 Agent，而是以下六项。

## GAP-01：Binary Logic 尚未正式进入 Agent Runtime

需要完成：

```text
P4 Reverse
 ↓
P5 Logic
 ↓
Candidate
 ↓
Verification
 ↓
Evidence
 ↓
Report
```

优先级：

> P0

---

## GAP-02：Benchmark 数据集不足

需要建立：

```text
benchmarks/source/
benchmarks/binary/
benchmarks/fuzz/
```

每一个 Benchmark 应至少记录：

```text
sample_id
source
language
target_type
ground_truth
cwe
expected_findings
authorization
run_command
```

优先级：

> P0

---

## GAP-03：消融实验不足

至少需要完成以下实验：

### Experiment A

```text
Multi-Agent
vs
Single-Agent
```

### Experiment B

```text
Verification ON
vs
Verification OFF
```

### Experiment C

```text
Evidence Fusion
vs
LLM Only
```

### Experiment D

```text
Agent-Guided Fuzz
vs
Traditional Fuzz
```

指标建议：

```text
Precision
Recall
F1
False Positive Rate
Confirmed Finding Count
Uncertain Finding Count
Execution Time
Agent Steps
Token Cost
Coverage
Crash Count
Unique Crash Count
```

优先级：

> P0

---

## GAP-04：Persistence 未完成

目前主要 Task / Evidence / Report 为进程内状态。

服务重启之后：

```text
Task
Finding
Evidence
Report
```

可能丢失。

V0.3 可以接受。

但最终版本建议至少实现：

```text
SQLite
```

或：

```text
SQLite + Repository Adapter
```

不建议当前直接引入复杂分布式数据库。

优先级：

> P1

---

## GAP-05：完整真实课程 Demo 尚需系统验收

需要固定至少三个 Demo：

### Demo 1：Source

```text
Vulnerable Python Project
 ↓
Parser
 ↓
Audit
 ↓
Verification
 ↓
Report
 ↓
Frontend
```

### Demo 2：Binary

```text
Course Binary
 ↓
Reverse
 ↓
Logic
 ↓
Evidence
 ↓
Verification
```

### Demo 3：Fuzz

```text
Authorized Test Target
 ↓
Seed
 ↓
Mutation
 ↓
Crash
 ↓
Evidence
 ↓
Verification
```

优先级：

> P0

---

## GAP-06：创新机制缺乏量化证明

目前已经有创新机制，但部分仍停留在架构和代码层。

最终需要形成：

```text
Mechanism
   ↓
Experiment
   ↓
Metric
   ↓
Result
   ↓
Conclusion
```

否则答辩时容易变成：

> “我们的创新点是我们设计了 XX。”

应该升级成：

> “我们设计了 XX，并通过 XX 个测试样本验证，使误报率下降 XX%，或 Coverage 提升 XX%。”

---

# 14. VulnAgent 应重点保留的五个创新点

VulnAgent 不应该把创新点表述成：

```text
使用 LangChain
使用 LangGraph
调用 LLM
调用 Semgrep
调用 radare2
使用 React
```

这些属于技术栈，不属于真正的系统创新。

真正应该重点保留以下五个创新方向。

---

## Innovation 1：有界 Multi-Agent 漏洞分析编排

核心机制：

```text
Planner
 ↓
Supervisor
 ↓
AgentRouter
 ↓
Specialized Agents
```

同时引入：

```text
max_agent_steps
max_route_repeats
max_analysis_retries
```

解决普通 Agent 系统可能出现的：

- 无限循环；
- Agent Ping-Pong；
- 无意义重复分析；
- LLM 非法路由；
- 资源不可控。

可以总结为：

> **Bounded Multi-Agent Vulnerability Analysis Runtime**

这是 VulnAgent 的系统级创新基础。

---

# 15. Innovation 2：Independent Verification

传统模式：

```text
LLM Discovery
 ↓
LLM Conclusion
```

VulnAgent：

```text
Discovery Agent
 ↓
Candidate
 ↓
Evidence
 ↓
Independent Verification
 ↓
Reviewer
 ↓
Final Verdict
```

Verification 是：

```text
CONFIRMED
REJECTED
UNCERTAIN
```

唯一权威边界。

这一机制用于降低：

- LLM Hallucination；
- 静态分析误报；
- 单一工具误报；
- Fuzz Crash 误判。

建议作为课程答辩的核心创新点之一。

---

# 16. Innovation 3：Evidence First

VulnAgent 不允许：

```text
LLM：
“我认为这里存在 SQL 注入。”
```

直接变成漏洞结论。

而要求：

```text
Finding
 ↓
Evidence IDs
 ↓
Source Location
 ↓
Taint / Static / Runtime Signal
 ↓
Verification
 ↓
Report
```

实现：

> Finding → Evidence → Verification → Report

全过程可追踪。

这能够显著提高系统：

- 可解释性；
- 可复现性；
- 可审计性；
- 课程展示可信度。

---

# 17. Innovation 4：Static Analysis ↔ Dynamic Fuzz 联动

不要让：

```text
Source Audit
Binary Analysis
Fuzz
```

成为三个完全独立模块。

目标应逐步形成：

```text
Static Analysis
      ↓
Risk Region
      ↓
Planner
      ↓
Dynamic Validation
      ↓
Crash / Runtime Evidence
      ↓
Verification
```

例如：

```text
危险函数
 ↓
输入接口
 ↓
Seed Strategy
 ↓
Fuzz
```

或者：

```text
Binary High-value Function
 ↓
Planner
 ↓
Dynamic Validation
```

这比单纯“系统同时包含静态分析和 Fuzz”更具创新性。

---

# 18. Innovation 5：Multi-source Evidence Fusion

未来 Verification 不应该只计算：

```text
是否存在 Evidence
```

而可以进一步发展：

```text
Source Rule Evidence
+
AST Evidence
+
Taint Evidence
+
Binary Evidence
+
Runtime Evidence
+
Crash Evidence
+
LLM Semantic Evidence
      ↓
Evidence Fusion
      ↓
Confidence
```

最终形成：

> 多源异构安全证据融合机制。

这是非常适合作为课程设计自研算法部分继续深化的方向。

---

# 19. 创新性优先级

建议最终课程报告重点介绍：

| 创新 | 优先级 | 当前成熟度 |
|---|---:|---:|
| Evidence First | P0 | ★★★★★ |
| Independent Verification | P0 | ★★★★★ |
| Bounded Multi-Agent Runtime | P0 | ★★★★☆ |
| Static ↔ Dynamic 联动 | P0 | ★★★☆☆ |
| Evidence Fusion | P1 | ★★★☆☆ |
| Agent-Guided Fuzz | P1 | ★★☆☆☆ |
| Binary Semantic Localization | P1 | ★★☆☆☆ |

---

# 20. 下一阶段开发优先级

从现在开始不建议九个人继续无序增加功能。

推荐：

```text
V0.3 Release Candidate
```

按照以下顺序推进。

## P0-1

完成真实 Source 主链最终验收：

```text
Task
 ↓
Source Parser
 ↓
Source Audit
 ↓
Candidate
 ↓
Evidence
 ↓
Verification
 ↓
Reviewer
 ↓
Report
 ↓
Frontend
```

---

## P0-2

完成 P4 + P5 Binary 正式集成：

```text
Binary Reverse
 ↓
Binary Logic
 ↓
Candidate
 ↓
Evidence
 ↓
Verification
```

---

## P0-3

建立 Benchmark。

至少建立：

```text
10～20 Source Samples
5～10 Binary Samples
若干 Fuzz Demo Samples
```

---

## P0-4

完成第一轮消融实验。

重点优先：

```text
Verification ON / OFF
```

因为这一项最容易体现当前项目已经形成的创新价值。

---

## P1-1

完善 Evidence Graph。

从：

```text
Finding
 ↓
Evidence List
```

增强为：

```text
Finding
 ├── Source Evidence
 ├── Static Evidence
 ├── Runtime Evidence
 ├── Verification Evidence
 └── Reviewer Evidence
```

---

## P1-2

实现 Agent-Guided Fuzz MVP。

不用追求工业级 Fuzz。

只需要证明：

```text
Static Analysis
      ↓
Risk Information
      ↓
Seed / Mutation Selection
      ↓
Fuzz
```

比随机基线有可观察差异。

---

## P1-3

实现最小 Persistence。

优先：

```text
Repository Protocol
       ↓
SQLite Adapter
```

而不是让 Core 直接依赖 SQLite。

---

# 21. 当前不建议继续做的事情

现阶段应避免：

- 大规模重构 AgentRuntime；
- 大规模修改 Contracts；
- 更换整个前端技术栈；
- 为每一种语言都写 Parser；
- 一开始实现工业级污点分析；
- 一开始实现工业级 Fuzzer；
- 自研完整反编译器；
- 加十几个没有实际能力的 Agent；
- 把第三方工具包装一层就宣称创新；
- 为了增加代码量重复已有模块；
- 在 RuntimeState 中增加业务数据；
- 让 LLM 直接确认漏洞。

---

# 22. 最终课程设计目标形态

最终建议系统形成：

```text
                    User
                      ↓
                 Web Platform
                      ↓
                   FastAPI
                      ↓
                  Orchestrator
                      ↓
              Planner / Supervisor
                      ↓
        ┌─────────────┼───────────────┐
        ↓             ↓               ↓
   Source Agent   Binary Agent    Fuzz Agent
        ↓             ↓               ↓
   Candidate       Candidate        Crash
        └─────────────┼───────────────┘
                      ↓
                  Evidence
                      ↓
           Independent Verification
                      ↓
                  Reviewer
                      ↓
                 Evidence Graph
                      ↓
              Structured Report
```

同时通过 Benchmark 得到：

```text
Multi-Agent vs Single-Agent

Verification vs No Verification

Evidence Fusion vs LLM Only

Agent-Guided Fuzz vs Random Fuzz
```

最终实现三个层面的完整性：

### 工程完整性

```text
能够真正运行。
```

### 安全完整性

```text
每个漏洞都能追溯 Evidence。
```

### 科研 / 创新完整性

```text
创新机制能够通过实验量化验证。
```

---

# 23. 当前阶段结论

当前 VulnAgent 已经完成最困难的第一步：

> 从“九个人分别写模块”转变为“一个统一 Contracts、统一 Runtime、统一 Evidence、统一 Verification 的真实多智能体系统”。

现在继续开发的重点不应再是扩大系统规模，而应该从：

```text
Feature Development
```

逐渐转为：

```text
Integration
      ↓
Real Samples
      ↓
Benchmark
      ↓
Ablation
      ↓
Stabilization
      ↓
Release
```

当前最值得集中资源完成的三件事情是：

```text
1. 冻结并验收真实 Source 主链

2. 打通 P4 + P5 Binary 主链

3. 建立 Benchmark 与创新性消融实验
```

如果这三件事情能够完成，VulnAgent 就能够从一个：

> “功能比较完整的课程项目”

提升为：

> **“具有明确自研架构、独立验证机制、证据驱动设计以及可量化创新实验的软件漏洞分析 Multi-Agent 系统”。**
