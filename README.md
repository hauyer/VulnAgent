# VulnAgent

VulnAgent 是基于大语言模型、多智能体协作、程序分析与独立验证的软件漏洞分析平台。本仓库当前实现 **V0.2 Multi-Agent Architecture Foundation**：在 V0.1 公共协议之上提供动态、可追踪、有界的 Agent 工作流。

> V0.2 的 Analyzer、Fuzz、Verification 和 Report 仍为明确标记的 Mock 实现，不代表真实漏洞扫描能力，不执行未知二进制，也不包含漏洞利用逻辑。

## Architecture

```text
API → TaskManager → Orchestrator → AgentRuntime (LangGraph)
                                  → Planner / Supervisor
                                  → Source or Binary Capability
                                  → optional authorized Mock Fuzz
                                  → Verification → Reviewer → Report
```

所有 Agent 继承统一 `BaseAgent`，通过 `AgentMessage` 通信；所有分析结果使用 `VulnerabilityCandidate`；证据通过 `Evidence` 独立保存；只有 Verification 边界能够产生最终状态。`RuntimeState` 只记录临时路由，业务数据始终位于 `AnalysisContext`。非法路由、重复路由和超出 `MAX_AGENT_STEPS` 都会确定性地进入 Report/Finish。

## Quick Start

需要 Python 3.11 或更高版本。

```bash
python -m venv .venv
python -m pip install -e ".[test]"
```

## Run Tests

```bash
pytest
```

## Run API

```bash
python -m vulnagent.main
# 或
uvicorn vulnagent.api.app:app --reload
```

访问 `http://127.0.0.1:8000/docs` 查看 OpenAPI 页面。

## API

- `GET /health`
- `POST /tasks`
- `GET /tasks`
- `GET /tasks/{task_id}`
- `POST /tasks/{task_id}/run`
- `GET /tasks/{task_id}/findings`
- `GET /tasks/{task_id}/evidence`
- `GET /tasks/{task_id}/report`
- `GET /tasks/{task_id}/events`
- `GET /tasks/{task_id}/trace`

以上接口同时提供 `/api` 前缀版本；无前缀路径继续作为 V0.1 兼容入口。

## Project Structure

核心代码位于 `src/vulnagent/`：`core` 负责任务生命周期和持久化协调，`agent_runtime` 负责 LangGraph、Supervisor、路由、策略与工具注册，`agents` 提供统一 Agent 决策适配层，`analyzers`、`fuzz`、`verification`、`evidence`、`llm` 和 `report` 提供可替换能力。

跨模块代码必须从 `vulnagent.contracts` 导入公共 DTO 与 Protocol。`vulnagent.core.models` 仅为旧代码保留兼容导出。九人 Owner 边界和依赖规则见 `docs/01_architecture/module_boundaries.md`。

V0.2 设计、边界与扩展点见 `docs/01_architecture/v0.2_architecture.md`。
