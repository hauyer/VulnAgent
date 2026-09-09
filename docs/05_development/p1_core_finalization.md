# P1 V0.2 Core Finalization

## Status

- P1-Core-01 — DONE: Task 生命周期、终态、失败收敛与重复运行保护。
- P1-Core-02 — DONE: 有界路由、重试限制、异常与非法路由安全回退。
- P1-Core-03 — DONE: CapabilityBundle、AgentRegistry、ToolRegistry 与显式依赖注入。
- P1-Core-04 — DONE: AgentMessage / DomainEvent 结构化 Trace、任务隔离与私有推理字段守卫。
- P1-Core-05 — DONE: Contracts、依赖方向、RuntimeState、Pipeline 与 Verification 权威边界守卫。
- P1-Core-06 — DONE: SOURCE、BINARY、授权 Fuzz 与失败路径 Mock 系统闭环。
- P1-Core-07 — DONE: Composition Root 身份保持、能力可替换与启动期失败检查。
- P1-Core-08 — DONE: Planner、Supervisor、Router 与 Runtime 职责和限制回归测试。
- P1-Core-09 — DONE: P1 与共享基础设施示例 Owner 范围补齐。
- P1-Core-10 — DONE: CI 显式执行 Contracts、Architecture 与全量测试门禁。

## Architecture Freeze

`Orchestrator` 继续独占 Task 生命周期与持久化；`AgentRuntime` 只执行有界路由；`Pipeline` 只执行并合并单个动态选择的 Agent stage；`RuntimeState` 不复制 Finding、Evidence、Verification 或 Report。Discovery 只能产生 Candidate，最终漏洞状态仍只由 Verification 边界写入。

Trace 只由 `AnalysisContext.messages` 和 `DomainEvent` 构成。EventBus 按 task 保存隔离的深复制快照；运行时与事件总线在结构边界拒绝私有模型推理字段，异常 Trace 只记录公共摘要和异常类型。

## V0.3 Capability Integration

P2-P7/P9 的真实能力只需实现 `vulnagent.contracts` 中既有 Protocol，通过 `CapabilityBundle` 传给 `build_application()`。Composition Root 会将同一实例绑定到 AgentRegistry 与 ToolRegistry；无需修改 Orchestrator、Pipeline 或 AgentRuntime。

P8 可读取 Task、最终 `AnalysisContext`、按 task 查询的 EventBus 时间线、AgentMessage、Evidence 和 Report。P9 可消费 Route、Agent 成败、retry/fallback/termination 摘要、Evidence ID 与结构化事件。API 展示、证据图、报告排版、Benchmark 和 Experiment 指标仍由对应 Owner 实现。

## Cross-owner Scope

本次收口未实现真实 Parser、Source Audit、Binary Analysis、Fuzz、Verification 算法、API/Frontend、Evidence Graph、Report UI 或 Experiment 能力；这些模块继续通过现有 Protocol 接入。
