# 九人并行开发模块边界

`contracts` 是唯一公共 DTO、Enum 和 Protocol 来源。Core 拥有 Task 生命周期；Agent Runtime 拥有临时图状态和跨 Agent 路由；Agent 只做决策和协议适配；业务能力模块不横向导入其他模块的具体类。

```text
API -> Core Orchestrator -> Agent Runtime -> Agent -> Capability Protocol
              |                    |            |              |
              +--------------------+---------> contracts <-----+
Adapter -> External Tool
```

跨 Agent 调度只能由 Orchestrator 委托给 Agent Runtime 发起。Runtime 不持久化业务数据、不写 TaskStatus、不执行具体分析算法。发现模块只能产生 `CANDIDATE`；只有 Verification 能写入最终确认或拒绝状态。Evidence 只理解统一 Evidence。

Owner 依次为：1 Core/Contracts/Agent Runtime/Planner，2 Source Parser，3 Source Audit，4 Binary Reverse/Common，5 Binary Obfuscation/Logic，6 Fuzz，7 Verification/Reviewer，8 API/Frontend，9 Evidence/Report/Benchmark/Experiment。具体路径见 `.github/CODEOWNERS.example`。

兼容期内 `vulnagent.core.models` 重新导出 `vulnagent.contracts`。旧 Mock 类保留；新集成代码只依赖 Protocol 和 Contracts。
