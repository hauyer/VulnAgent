# VulnAgent 九人协作与模块责任划分

## 1. 分工原则

九名成员采用模块 Owner 制。

Owner 对模块承担：

- 架构责任
- 公共接口责任
- 代码质量责任
- 测试责任
- 文档责任
- Pull Request Review 责任

Owner 并不意味着其他成员禁止修改对应模块。

跨模块开发应提前说明并通过 Pull Request 协作。

## 2. P1：总体架构与 Core

主要目录：

`src/vulnagent/core/`

主要任务：

- 系统总体架构
- Task 生命周期
- Pipeline
- Orchestrator
- State Manager
- Event Bus
- 公共上下文
- 各模块集成
- 公共 Schema 协调

负责保证：

从任务创建到报告输出的整体 Pipeline 可以正常运行。

## 3. P2：Multi-Agent Framework

主要目录：

`src/vulnagent/agents/`

主要任务：

- BaseAgent
- Agent Registry
- Agent 生命周期
- AgentMessage
- PlannerAgent
- Agent 状态
- Agent 调度
- Agent 通信机制

协调其他成员将具体分析能力接入 Agent Framework。

## 4. P3：Source Code Analysis

主要目录：

`src/vulnagent/analyzers/source/`

主要任务：

- 语言识别
- AST
- CFG
- Call Graph
- Dangerous API
- Data Flow
- Taint Analysis
- Source/Sink
- 静态漏洞候选生成

优先支持：

- C
- C++
- Python

输出必须统一为：

`VulnerabilityCandidate`

## 5. P4：Binary Analysis

主要目录：

`src/vulnagent/analyzers/binary/`

主要任务：

- PE / ELF 识别
- Binary Metadata
- Imports
- Exports
- Strings
- Functions
- Instructions
- CFG
- Packer Detection
- Obfuscation Detection
- Binary Vulnerability Candidate

不得在初期自行实现完整反编译器。

允许通过 Adapter 获取底层分析结果。

## 6. P5：Fuzzing

主要目录：

`src/vulnagent/fuzz/`

主要任务：

- Seed Corpus
- Seed Generator
- Mutator
- Executor Adapter
- Coverage
- Crash Collector
- Crash Analyzer
- Agent-Guided Fuzz

所有目标程序必须运行于受控环境。

## 7. P6：Verification & Evidence

主要目录：

- `src/vulnagent/verification/`
- `src/vulnagent/evidence/`

主要任务：

- 漏洞复核
- 去误报
- 去重
- Severity
- Confidence 更新
- Evidence Collector
- Evidence Chain
- Verification Result

只有本模块有权将漏洞从：

`CANDIDATE`

变更为：

`CONFIRMED`

## 8. P7：LLM & Knowledge

主要目录：

- `src/vulnagent/llm/`
- `src/vulnagent/knowledge/`

主要任务：

- BaseLLM
- DeepSeek Adapter
- GLM Adapter
- Kimi Adapter
- MockLLM
- Prompt Manager
- Model Router
- CWE Knowledge
- CVE Knowledge
- Vulnerability Pattern

不得让业务逻辑依赖具体模型。

## 9. P8：Platform & Storage

主要目录：

- `src/vulnagent/api/`
- `src/vulnagent/storage/`
- `src/web/`

主要任务：

- FastAPI
- Task API
- Findings API
- Report API
- Database
- Web UI
- Dashboard
- Agent Workflow Visualization

平台展示必须读取真实 Backend 状态，而不是写死 Demo 数据。

## 10. P9：Experiment & Testing

主要目录：

- `tests/`
- `experiments/`
- `benchmarks/`
- `.github/`

主要任务：

- pytest
- Integration Tests
- System Tests
- Benchmark
- Experiment Config
- Metrics
- Ablation
- CI
- Regression
- Result Collection

负责保证实验：

**可复现、可比较、可追踪。**

## 11. 第一阶段共同任务

V0.1 前所有人不得立即开发复杂算法。

首先共同冻结：

1. Task Schema
2. AgentMessage Schema
3. VulnerabilityCandidate Schema
4. Evidence Schema
5. Pipeline Lifecycle

冻结后进入并行开发。

## 12. 分支约定

```text
P1: feature/core-pipeline
P2: feature/agent-framework
P3: feature/source-analysis
P4: feature/binary-analysis
P5: feature/fuzz-engine
P6: feature/verification
P7: feature/llm-knowledge
P8: feature/platform
P9: feature/experiments
```
