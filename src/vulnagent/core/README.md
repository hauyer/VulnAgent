# Core / Orchestrator（成员 1）

负责 Task 生命周期、Pipeline、状态、事件、上下文、Agent 调度和系统集成。输入输出均使用 Contracts，通过依赖注入组合能力。禁止在 Core 内实现分析、Fuzz 或验证算法。测试入口：`pytest tests/unit tests/integration`。
