# VulnAgent 九人并行开发与模块责任划分

本文件是 V0.1 九人 Owner 边界的权威说明。具体依赖约束见 `docs/01_architecture/module_boundaries.md`，机器可执行守卫见 `tests/architecture/`。

## 共同规则

- Owner 对本模块接口、实现、测试、文档和 PR Review 负责。
- 日常开发只修改 Owner 目录；跨目录修改必须最小化并邀请相关 Owner Review。
- 公共模型只来自 `vulnagent.contracts`，不得创建 MyFinding、AuditFinding 等平行协议。
- Agent 不直接调用 Agent；跨 Agent 编排只由 Orchestrator 完成。
- 具体工具只通过 Adapter 接入。
- 每个能力必须提供 Mock，使主分支始终可集成和测试。

## 成员 1：Core / Orchestrator

Owner：`src/vulnagent/core/`、公共 Contracts 协调、`agents/base.py`、`agents/registry.py`、`agents/planner_agent.py`、`main.py`。

负责 Task 生命周期、Pipeline、状态管理、事件总线、上下文、Agent 调度和系统集成。不得在 Core 实现分析算法。公共 Contract 修改必须同步契约测试和协议文档。

## 成员 2：Source Parser

Owner：`src/vulnagent/analyzers/source/parser/`。

负责项目导入、语言识别、目录解析、AST、符号、依赖和基础调用图。输入 `ProjectInput`，输出 `SourceAnalysisResult`。不得判断漏洞或调用 Audit、Verification、Fuzz、具体 LLM 厂商。

## 成员 3：Source Audit

Owner：`src/vulnagent/analyzers/source/audit/`、Semgrep Adapter。

负责危险 API、Source/Sink、数据流、污点、规则、语义审计和 Candidate 构建。只消费 `SourceAnalysisResult`，只输出 `VulnerabilityCandidate(CANDIDATE)`，不得确认漏洞。

## 成员 4：Binary Reverse

Owner：`src/vulnagent/analyzers/binary/common/`、`binary/reverse/`、Ghidra/radare2/UPX Adapter。

负责 PE/ELF、架构、区段、导入导出、字符串、熵、壳检测、函数与基础 CFG，输出 `BinaryAnalysisResult`。不负责复杂混淆语义、业务逻辑识别或漏洞确认。

## 成员 5：Obfuscation / Logic

Owner：`src/vulnagent/analyzers/binary/obfuscation/`、`binary/logic/`。

只消费 `BinaryAnalysisResult`，负责混淆特征和认证、密码学、注册等逻辑定位。不得重新执行基础二进制解析，不得依赖 Reverse 具体类。

## 成员 6：Dynamic / Fuzz

Owner：`src/vulnagent/fuzz/`。

负责 Seed、Mutation、Executor、Coverage、Crash 和受控动态分析。输入 `FuzzRequest`，输出 `FuzzResult` 与 Evidence。真实执行必须明确授权并位于沙箱；不得确认漏洞。

## 成员 7：Verification

Owner：`src/vulnagent/verification/`、`agents/verification_agent.py`、`agents/reviewer_agent.py`。

消费 `VulnerabilityCandidate + VerificationContext`，输出 `VerificationResult`。只有本边界可以写入 `CONFIRMED` 或 `REJECTED`。不得反向依赖 Source、Binary、Fuzz 的具体实现。

## 成员 8：Platform / Frontend

Owner：`frontend/`，协作维护 `src/vulnagent/api/`。

Frontend 只通过 API 读取 Task、Finding、Evidence、VerificationResult、Report 和 Trace。不得导入 Backend 内部类或读取 Analyzer 文件。

## 成员 9：Evidence / Report / Benchmark

Owner：`src/vulnagent/evidence/`、`src/vulnagent/report/`、`benchmarks/`、`experiments/`。

Evidence 负责收集、关联、存储、查询和证据图；Report 只消费公共 Contracts；实验负责可复现评测。不得依赖具体工具或 Agent 内部对象。

## 分支建议

```text
feature/core-pipeline
feature/source-parser
feature/source-audit
feature/binary-reverse
feature/binary-logic
feature/fuzz-engine
feature/verification
feature/platform
feature/evidence-report-experiments
```

真实 GitHub 用户名确定后，将 `.github/CODEOWNERS.example` 替换为 `.github/CODEOWNERS` 并启用强制 Review。
