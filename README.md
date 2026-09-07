# VulnAgent

VulnAgent 是基于大语言模型、多智能体协作、程序分析与独立验证的软件漏洞分析平台。本仓库当前实现 **V0.1 Architecture Skeleton**，目标是冻结公共协议并提供可运行、可测试、可扩展的单机工程基础。

> V0.1 的 Analyzer、Fuzz、Verification 和 Report 均为明确标记的 Mock 实现，不代表真实漏洞扫描能力，不执行未知二进制，也不包含漏洞利用逻辑。

## Architecture Skeleton

```text
Task → Planner → Source/Binary Mock Analysis → Mock Fuzz
     → Independent Mock Verification → Reviewer → Report → Completed
```

所有 Agent 继承统一 `BaseAgent`，通过 `AgentMessage` 通信；所有分析结果使用 `VulnerabilityCandidate`；证据通过 `Evidence` 独立保存；只有 Verification 阶段能够改变候选漏洞状态。

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

以上接口同时提供 `/api` 前缀版本；无前缀路径为 V0.1 兼容入口。

## Project Structure

核心代码位于 `src/vulnagent/`：`core` 负责任务和调度，`agents` 提供统一 Agent 框架，`analyzers`、`fuzz`、`verification`、`evidence`、`llm` 和 `report` 提供可替换能力，`api` 暴露 FastAPI 接口，`storage` 提供 V0.1 内存存储。

跨模块代码必须从 `vulnagent.contracts` 导入公共 DTO 与 Protocol。`vulnagent.core.models` 仅为旧代码保留兼容导出。九人 Owner 边界和依赖规则见 `docs/01_architecture/module_boundaries.md`。

设计约束与协议详见 `AGENTS.md` 和 `docs/`。
