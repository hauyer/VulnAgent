# Core / Orchestrator（成员 1）

Core 负责 VulnAgent 的系统级任务生命周期，包括：

- Task 生命周期
- TaskStatus 状态转换
- Pipeline / Agent Runtime 生命周期桥接
- DomainEvent 事件传递
- AnalysisContext 管理
- Task 持久化接口协调
- 系统级异常收敛
- 重复执行与并发执行保护

Core 只负责编排和生命周期，不实现 Source Analysis、Binary Analysis、Fuzz、Verification 等具体算法。

## Lifecycle

正常任务：

CREATED
→ PROFILING
→ PLANNING
→ ANALYZING
→ DYNAMIC_TESTING / VERIFYING
→ REPORTING
→ COMPLETED

异常任务：

任意活动状态
→ FAILED

COMPLETED 与 FAILED 均为终态，不允许重新进入生命周期。

当前 V0.2 不实现 checkpoint resume。处于非 CREATED 活动态的任务不允许直接重新启动。

## Reliability Rules

1. 同一个 task_id 不允许并发运行。
2. COMPLETED / FAILED 任务不允许重新运行。
3. 任务失败后必须尽最大努力进入 FAILED。
4. 失败任务的 AnalysisContext 必须保留用于追踪。
5. Event subscriber 故障不得破坏主生命周期。
6. TaskRepository 返回隔离副本，避免外部绕过状态机修改持久化状态。

## Tests

运行 Core 单元与集成测试：

```bash
python -m pytest tests/unit tests/integration