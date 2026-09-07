# VulnAgent 系统总体架构

## 1. 架构目标

系统架构应满足：

- 多人并行开发
- 模块低耦合
- Agent 可扩展
- LLM 可替换
- 分析器可替换
- 支持源码与二进制
- 支持静态与动态结果融合
- 支持可验证证据链
- 支持自动实验

## 2. 分层架构

VulnAgent 采用六层结构。

### Layer 1：Interface

API / Web / CLI

负责用户交互。

### Layer 2：Orchestration

Core / Agent Runtime / Pipeline / Supervisor / Planner

负责：

- 创建任务
- 通过有界状态图动态调度 Agent
- 管理状态
- 聚合结果

### Layer 3：Agent

包括：

- PlannerAgent
- SourceAuditAgent
- BinaryAnalysisAgent
- FuzzAgent
- VerificationAgent
- ReviewerAgent
- ReportAgent

负责面向安全任务进行决策和推理。

### Layer 4：Capability

实际能力模块：

- Source Analyzer
- Binary Analyzer
- Fuzz Engine
- Verification
- Evidence
- Knowledge
- Report

### Layer 5：Provider

外部能力抽象：

- LLM Provider
- Disassembler Adapter
- Fuzz Backend
- Sandbox
- Database
- External Knowledge

### Layer 6：Infrastructure

包括：

- Config
- Logging
- Storage
- Cache
- CI
- Container
- Tests

## 3. 总体数据流

```text
User
 │
 ▼
API
 │
 ▼
TaskManager
 │
 ▼
Orchestrator
 │
 ▼
PlannerAgent
 │
 ├──────────────┐
 ▼              ▼
SourceAgent   BinaryAgent
 │              │
 ▼              ▼
Analyzer       Analyzer
 │              │
 └──────┬───────┘
        ▼
VulnerabilityCandidate[]
        │
        ├─────────────┐
        ▼             ▼
     FuzzAgent    EvidenceCollector
        │             │
        ▼             │
 Runtime Evidence ────┘
        │
        ▼
VerificationAgent
        │
        ▼
ReviewerAgent
        │
        ▼
Confirmed Findings
        │
        ▼
ReportAgent
        │
        ▼
Final Report
```

## 4. Core

### TaskManager

负责：

- create_task
- get_task
- update_task
- cancel_task

### Orchestrator

负责：

- 读取 Task
- 调用 Planner
- 调度 Agent
- 聚合 Agent Result
- 推进状态机

### Pipeline

建议阶段：

- CREATED
- PROFILING
- PLANNING
- ANALYZING
- DYNAMIC_TESTING
- VERIFYING
- REPORTING
- COMPLETED
- FAILED

## 5. Target

Target 是被分析对象。

至少包括：

- target_id
- path
- target_type
- language
- file_format
- metadata
- execution_policy

`target_type`：

- SOURCE
- BINARY
- PROJECT
- ARCHIVE

## 6. Agent Architecture

所有 Agent 继承 `BaseAgent`。

基本接口：

```python
class BaseAgent:

    async def run(
        self,
        task: Task,
        context: AnalysisContext,
    ) -> AgentResult:
        ...
```

Agent 不应该直接修改全局数据。

Agent 返回 `AgentResult`。

由 Orchestrator 负责状态更新。

## 7. AnalysisContext

Context 用于存储任务运行时上下文。

包含：

- task
- target
- artifacts
- findings
- evidence
- agent_history

应避免随意使用 dict。

关键字段应明确建模。

## 8. Analyzer

Analyzer 不等于 Agent。

例如：

`SourceAuditAgent`

负责决定：

**需要分析什么。**

`SourceAnalyzer`

负责执行：

**AST / Call Graph / Rule Scan**

这样保证 Reasoning 与 Capability 解耦。

## 9. Verification

所有 Candidate 默认不可信。

Verification 根据：

- 静态路径
- 代码位置
- Fuzz
- Runtime Trace
- Crash
- 多 Analyzer 结果
- 模型复核

判断：

- CONFIRMED
- REJECTED
- UNCERTAIN

## 10. Evidence

所有证据独立存储。

Finding 只保存：

`evidence_ids`

避免 VulnerabilityCandidate 中存储大量日志和二进制内容。

## 11. Report

Report 层只读取已经结构化的：

- Task
- Finding
- Evidence
- Experiment Metadata

不能重新执行漏洞检测。

## 12. V0.2 Dynamic Mock Workflow

V0.2 已实现：

```text
POST /tasks → Orchestrator → AgentRuntime → Planner
                                      ├→ Source Analysis
                                      └→ Binary Analysis
                                             ↓
                              optional authorized Mock Fuzz
                                             ↓
                             Verification → Reviewer → Report
```

零发现时 Analysis 可直接进入 Report；证据不足时 Verification 可请求一次受限补充分析；非法或重复路由会确定性回退到 Report/Finish。LangGraph State 不替代公共 Contract 或持久化模型。

这样多人开发不会互相阻塞。

## 13. 架构约束

禁止：

- Agent → 直接调用 Web UI
- Analyzer → 直接修改数据库
- LLM Adapter → 修改业务状态
- Report → 修改 VulnerabilityCandidate
- Fuzz Engine → 直接确认漏洞

状态修改必须由 Core / Verification 管理。

## 14. 可扩展性

未来新增：

`SymbolicExecutionAgent`

只需要：

1. 实现 BaseAgent
2. 注册 Agent
3. 定义输入输出
4. 在 Agent Runtime 注册结构化 Route

而不应修改所有已有模块。
