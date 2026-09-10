# VulnAgent V0.3

VulnAgent 是一个 Evidence First 的多智能体软件漏洞分析课程项目。V0.3
在冻结 V0.1 公共协议和 V0.2 Agent Runtime 的基础上，打通真实 Python
源码分析、独立验证、结构化报告、FastAPI 与 React 展示链路。

## Architecture

```text
React / Vite
    -> /api
FastAPI
    -> TaskRepository / EvidenceRepository（唯一状态源）
    -> Core Orchestrator（唯一正式业务 Orchestrator）
    -> AgentRuntime / Supervisor（有界路由）
    -> CapabilityBundle
    -> Parser / Auditor / Binary / optional Fuzz
    -> EvidenceVerifier -> Reviewer -> StructuredReportGenerator
```

发现模块只产生 `CANDIDATE`。只有 Verification 可以写入 `CONFIRMED`、
`REJECTED` 或 `UNCERTAIN`。报告只消费已有 Task、Candidate、Evidence、
Verification 与 Trace，不自行判断漏洞。运行轨迹不保存模型私有推理。

## Profiles

通过 `VULNAGENT_PROFILE` 显式切换：

- `mock`：确定性的 Mock Parser、Auditor、Binary、Fuzz 与 Verifier，供单元
  测试、架构测试及无外部能力环境使用。
- `v03-source`（默认）：真实 `SourceProjectParser`、`PythonSourceAuditor`、
  `EvidenceVerifier`、`StructuredReportGenerator`；同时启用不执行目标的
  PE/ELF 静态读取，以及必须显式授权的本地受控 Fuzz。

默认有界参数为：

```text
MAX_AGENT_STEPS=15
MAX_ROUTE_REPEATS=2
MAX_ANALYSIS_RETRIES=1
```

## Installation

需要 Python 3.11+ 与 Node.js 22：

```bash
python -m pip install -e ".[test]"
npm ci
```

复制 `.env.example` 为本地 `.env` 后可调整 Profile。不要提交真实密钥。
当前 LLM Router 支持已实现的 Provider 配置；默认 `mock` 不需要 API Key。

## Run Backend

```bash
python -m vulnagent.main
```

FastAPI 默认监听 `http://127.0.0.1:8000`，OpenAPI 位于
`http://127.0.0.1:8000/docs`。

## Run Frontend

另开终端：

```bash
npm run dev
```

访问 `http://127.0.0.1:5173`。Vite 只负责 UI 与 `/api` 代理，不保存任务
状态，也不执行分析、验证或报告逻辑。

## API

- `GET /api/health`
- `GET /api/tasks`
- `POST /api/tasks`
- `GET /api/tasks/{task_id}`
- `POST /api/tasks/{task_id}/run`
- `GET /api/tasks/{task_id}/events`
- `GET /api/tasks/{task_id}/trace`
- `GET /api/tasks/{task_id}/findings`
- `GET /api/tasks/{task_id}/evidence`
- `GET /api/tasks/{task_id}/verifications`
- `GET /api/tasks/{task_id}/report`

无 `/api` 前缀的旧入口暂时保留作向后兼容；前端统一使用 `/api`。

## V0.3 Source Demo

一键执行真实 Source 主链：

```bash
python scripts/demo_source_v03.py
```

脚本通过正式 Application/Orchestrator 分析 `samples/source_demo/`，输出真实
Task ID、候选、Verification 结果和 Report 摘要，不硬编码漏洞结论。示例同时
包含参数化 SQL、`shell=False` 参数列表、安全 JSON 和有界路径等反例。

前端手工验收：启动后端和前端，在 Dashboard 创建目标路径
`samples/source_demo`、类型选择 `source` 并运行；依次查看 Dashboard、Agent
Topology、Evidence Chain、Vulnerabilities、Report、Event Trace 与 API Console。

## Binary Demo

`samples/binary_demo/` 提供 C 源码与构建命令。编译后创建 `binary` Task。
内置分析器真实读取 PE/ELF 头、导入和有界字符串，但不执行目标。radare2 与
UPX 是可选外部工具；未安装时必须明确降级，不能伪造执行结果。单一静态风险
信号通常由 P7 判为 `UNCERTAIN`，而不是越权确认。

## Controlled Fuzz Demo

`samples/fuzz_demo/` 只用于本地授权课程演示。动态执行必须同时设置目标
metadata：

```json
{
  "fuzz_authorized": true,
  "dynamic_validation": true,
  "seed_dir": "samples/fuzz_demo/seeds"
}
```

执行时间和输出有界，网络策略默认关闭；异常退出转换为 `CRASH_LOG` Evidence，
再交由 Verification 判定。禁止用于互联网、未知程序、未授权目标或自动利用。

## Tests

```bash
python -m pytest tests/contracts -q
python -m pytest tests/architecture -q
python -m pytest -q
npm ci
npm run lint
npm run build
```

CI 同时执行全部 Python 门禁和前端类型检查/生产构建。

## Current Limitations

- 深度结构和语义 Source Audit 目前主要支持 Python；其他语言可识别，但结构化
  解析覆盖不同，不宣称完整 C/C++/Java/Go 语义审计。
- radare2、UPX 为可选工具；内置 Binary 能力以不执行目标的结构解析为主。
- Fuzz 演示仅限本地、明确授权、受控目标；当前沙箱是进程级安全边界，不等同
  于完整虚拟机隔离。
- 真实 LLM Provider 需要对应 API Key；缺失时应使用 `mock` 或明确不可用。
- Task、Evidence 与 Report 当前为进程内存储，服务重启后不会持久化。

更完整的边界说明见 `docs/01_architecture/v0.3_integration.md`。
