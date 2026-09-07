# AGENTS.md

# VulnAgent Repository Instructions

## 1. 项目简介

VulnAgent 是“网络空间安全课程设计”项目中的自研软件漏洞挖掘系统。

项目目标是设计并实现一套基于大语言模型与多智能体协同的软件漏洞分析平台，面向源代码与二进制程序，综合静态分析、动态测试、模糊测试、漏洞复核、证据链构建和自动报告等能力。

系统总体流程为：

```text
Target
→ Program Understanding
→ Static / Binary Analysis
→ Agent Reasoning
→ Fuzzing
→ Vulnerability Candidate
→ Independent Verification
→ Evidence Chain
→ Report
```

本项目不是简单的大模型 API 封装，也不是已有漏洞扫描器的二次包装。

## 2. 总体开发原则

所有开发人员以及 Codex、Claude Code、Cursor 等代码 Agent 必须遵守本文件。

### 2.1 自研优先

以下模块必须体现本项目自己的设计：

- 多智能体任务编排机制
- Agent 通信协议
- 统一任务状态模型
- 漏洞候选统一 Schema
- 漏洞证据统一 Schema
- 独立漏洞复核机制
- 多来源结果融合机制
- 静态分析与 Fuzz 联动机制
- 实验评测框架
- 最终报告生成流程

允许调用第三方基础工具获取底层信息，但第三方工具不能替代 VulnAgent 的核心架构。

允许示例：

- 使用现有反汇编工具获得函数与指令信息
- 使用现有 Fuzz 引擎作为底层执行器
- 使用 DeepSeek、GLM、Kimi 等模型作为推理引擎
- 使用 CWE/CVE 数据作为安全知识来源
- 使用 Tree-sitter、LLVM 等工具辅助解析程序

不允许：

- 直接将现有漏洞扫描器包装成项目主体
- 只调用一次大模型判断“有没有漏洞”
- 将多个 Prompt 顺序调用包装成“多智能体”
- 将第三方项目 UI 更换后作为自研成果

## 3. 当前版本目标

当前工程阶段为：

**V0.1 — Architecture Skeleton**

V0.1 的目标不是完成真实漏洞挖掘能力，而是建立稳定、可测试、可扩展的工程骨架。

V0.1 必须完成：

1. 项目目录结构
2. 统一配置系统
3. FastAPI 服务入口
4. Task Schema
5. AgentMessage Schema
6. VulnerabilityCandidate Schema
7. Evidence Schema
8. Agent 基类
9. Mock Agent
10. Pipeline / Orchestrator
11. LLM Adapter 抽象层
12. 基础存储接口
13. 单元测试框架
14. CI
15. 日志体系
16. 基础文档

V0.1 不要求完成：

- 完整污点分析
- 完整二进制反编译
- 真正漏洞利用
- 自动生成攻击载荷
- 高级 Fuzz 变异策略
- 真实恶意软件执行

## 4. 总体系统模块

### Core

负责：

- Task 生命周期
- Pipeline 调度
- Agent 调度
- 状态管理
- 事件传递
- 任务上下文

目录：

`src/vulnagent/core/`

### Agents

负责：

- Planner Agent
- Source Audit Agent
- Binary Analysis Agent
- Fuzz Agent
- Verification Agent
- Reviewer Agent
- Report Agent

目录：

`src/vulnagent/agents/`

### Source Analysis

负责：

- AST
- CFG
- Call Graph
- Data Flow
- Taint Analysis
- 危险 API
- 静态规则
- LLM 语义分析

目录：

`src/vulnagent/analyzers/source/`

### Binary Analysis

负责：

- PE / ELF 信息
- Strings
- Imports
- Functions
- Instructions
- CFG
- Packer Detection
- Obfuscation Detection

目录：

`src/vulnagent/analyzers/binary/`

### Fuzz

负责：

- Attack Surface
- Seed Corpus
- Mutation
- Execution
- Coverage
- Crash
- Crash Analysis

目录：

`src/vulnagent/fuzz/`

### Verification

负责：

- 漏洞去重
- 漏洞复核
- 去误报
- Confidence 更新
- Severity
- Evidence Validation

目录：

`src/vulnagent/verification/`

### Evidence

负责统一证据链。

目录：

`src/vulnagent/evidence/`

### LLM

负责统一模型调用。

目录：

`src/vulnagent/llm/`

业务代码不得直接调用具体厂商 API。

## 5. Agent 设计原则

所有 Agent 必须继承统一 `BaseAgent`。

Agent 不得直接依赖其他 Agent 的具体实现。

Agent 之间通过结构化消息进行通信。

正式通信必须使用 `AgentMessage`，基本字段包括：

- message_id
- task_id
- sender
- receiver
- message_type
- payload
- evidence_ids
- timestamp

自然语言可以存在于 payload 中，但不能替代结构化协议。

## 6. 漏洞候选统一原则

所有检测模块都必须输出统一的：

`VulnerabilityCandidate`

无论漏洞来自：

- Source Analyzer
- Binary Analyzer
- Fuzz
- LLM
- Rule Engine
- External Tool Adapter

都不得自行定义不同漏洞结果格式。

`VulnerabilityCandidate` 至少包含：

- vulnerability_id
- task_id
- vulnerability_type
- cwe_id
- title
- description
- target
- location
- source_agent
- confidence
- evidence_ids
- status

## 7. 漏洞状态

统一状态为：

- CANDIDATE
- VERIFYING
- CONFIRMED
- REJECTED
- UNCERTAIN

发现模块不能直接将状态设置为 `CONFIRMED`。

只有 Verification 层可以确认漏洞。

## 8. Evidence First 原则

LLM 的自然语言结论不是充分证据。

每个正式漏洞结果必须关联 Evidence。

Evidence 类型可以包括：

- SOURCE_LOCATION
- CODE_SNIPPET
- CALL_PATH
- DATA_FLOW
- TAINT_PATH
- BINARY_ADDRESS
- DISASSEMBLY
- CFG_PATH
- FUZZ_INPUT
- COVERAGE
- CRASH_LOG
- STACK_TRACE
- SANITIZER_OUTPUT
- RUNTIME_TRACE
- TOOL_RESULT
- MODEL_REASONING_SUMMARY
- VERIFICATION_RESULT

`MODEL_REASONING_SUMMARY` 只能作为辅助证据，不能单独证明漏洞成立。

## 9. Independent Verification

发现 Agent 与验证 Agent 必须解耦。

```text
SourceAuditAgent
→ VulnerabilityCandidate
→ VerificationAgent
→ CONFIRMED / REJECTED / UNCERTAIN
```

ReviewerAgent 可对高风险或冲突结果进行第二次复核。

## 10. Fuzz 安全原则

Fuzz 模块当前只允许：

- 本地课程实验程序
- 明确授权测试程序
- 自己编写的 Benchmark
- 开源测试程序
- 沙箱内目标

禁止默认执行未知程序。

不得在宿主系统直接运行潜在恶意二进制。

## 11. 漏洞验证安全原则

V0.1 阶段不要实现自动攻击能力。

PoC / Exploit 相关模块当前只允许提供：

- 接口
- Mock
- 状态定义
- 受控验证流程

不得默认：

- 攻击公网目标
- 自动扫描互联网
- 横向移动
- 持久化
- 绕过权限
- 自动攻击第三方系统

## 12. LLM Adapter

所有模型通过：

`src/vulnagent/llm/`

统一访问。

统一抽象：

`BaseLLM`

候选 Adapter：

- DeepSeekAdapter
- GLMAdapter
- KimiAdapter
- MockLLM

业务代码只能依赖统一接口。

## 13. 编码规范

Python：

- Python >= 3.11
- 使用 type hints
- 使用 Pydantic v2
- 使用 pathlib
- 使用 logging
- 避免 print
- 避免全局可变状态
- 公共接口必须有 docstring
- 核心 Schema 必须有测试
- 模块职责必须单一

推荐：

- FastAPI
- Pydantic
- pytest
- httpx
- PyYAML
- SQLAlchemy

## 14. 配置原则

API Key、模型 URL、数据库密码、Token、Secret 不得写死在代码中。

使用 `.env`，并提交 `.env.example`。

禁止提交真实 `.env`。

## 15. Git 原则

禁止直接提交 main。

分支结构：

```text
main
└── develop
    ├── feature/core-pipeline
    ├── feature/agent-framework
    ├── feature/source-analysis
    ├── feature/binary-analysis
    ├── feature/fuzz-engine
    ├── feature/verification
    ├── feature/llm-knowledge
    ├── feature/platform
    └── feature/experiments
```

Commit：

```text
feat(scope): description
fix(scope): description
docs(scope): description
test(scope): description
refactor(scope): description
chore(scope): description
```

## 16. 修改安全原则

任何 Coding Agent 修改代码前必须：

1. 阅读 AGENTS.md
2. 阅读相关 docs
3. 查看当前已有实现
4. 明确本次修改范围
5. 尽量增量修改

禁止：

- 未经允许删除已有功能
- 未经允许全仓库重构
- 为了“统一风格”重写大量工作代码
- 擅自修改公共 Schema
- 擅自改变公共 API
- 擅自删除测试

## 17. 公共 Schema 变更规则

以下内容属于冻结接口：

- Task
- AgentMessage
- VulnerabilityCandidate
- Evidence

修改前必须：

1. 分析影响模块
2. 更新文档
3. 更新所有测试
4. 保持必要的向后兼容
5. 明确说明修改原因

## 18. 测试要求

至少包含：

- `tests/unit/`
- `tests/integration/`
- `tests/system/`

V0.1 最低要求：`pytest` 能够完整通过。

## 19. Definition of Done

一个功能只有满足以下条件才算完成：

- 代码实现完成
- 类型定义正确
- 基础异常处理存在
- 测试通过
- 文档更新
- 不破坏已有功能
- 不提交敏感信息
- 能够复现

## 20. 开发优先级

发生冲突时遵循：

```text
正确性
> 安全性
> 可维护性
> 可解释性
> 可扩展性
> 性能
> UI 美观
```

课程设计的创新必须可以：

```text
设计
→ 实现
→ 实验
→ 对比
→ 解释
```

## 21. 模块所有权与解耦规则

1. 优先修改自己的 Owner 目录；跨模块修改必须最小化。
2. 禁止重新定义公共 Schema；公共模型统一从 `vulnagent.contracts` 导入。
3. `contracts/` 中标有 `PUBLIC CONTRACT` 的文件属于冻结协议，变更必须同步影响分析、文档和契约测试。
4. 禁止跨模块直接 import 具体实现，使用 Protocol、依赖注入、结构化事件或兼容 Adapter。
5. 跨 Agent 调度只能经过 Orchestrator；Agent 不直接调用另一个 Agent。
6. Analyzer 不调用 Verification；发现模块不得输出 `CONFIRMED`。
7. Verification 是 `CONFIRMED` 和 `REJECTED` 状态的唯一写入者。
8. Evidence 不依赖具体分析工具；Report 只消费 Task、Finding、VerificationResult 和 Evidence。
9. Frontend 只通过 API 访问后端数据，不 import 后端内部实现。
10. 第三方工具必须位于 Adapter 边界之后，业务模块不得直接调用厂商 API 或工具进程。
11. 每个能力模块必须提供可独立测试的接口和 Mock。
12. 公共协议修改必须同步更新文档、契约测试并尽量保持向后兼容。
