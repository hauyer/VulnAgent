# VulnAgent V0.3

VulnAgent 是一个 Evidence First 的多智能体软件漏洞分析课程项目。V0.3
在冻结 V0.1 公共协议和 V0.2 Agent Runtime 的基础上，打通真实 Python
源码分析、独立验证、结构化报告、FastAPI 与 React 展示链路。

## Architecture

```text
React / Vite
    -> /api
FastAPI
    -> TaskRepository / EvidenceRepository / ContextRepository（唯一状态源）
    -> Core Orchestrator（唯一正式业务 Orchestrator）
    -> AgentRuntime / Supervisor（有界路由）
    -> CapabilityBundle
    -> Parser / Auditor / Binary Reverse + Logic + Obfuscation / optional Fuzz
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
  PE/ELF 静态读取、`binary.logic`/`binary.obfuscation` 语义分析，以及必须
  显式授权的本地受控 Fuzz。

默认有界参数为：

```text
MAX_AGENT_STEPS=15
MAX_ROUTE_REPEATS=2
MAX_ANALYSIS_RETRIES=1
```

存储默认使用 `memory`。需要跨进程恢复课程演示数据时可在 `.env` 中启用：

```text
STORAGE_BACKEND=sqlite
SQLITE_PATH=artifacts/vulnagent.db
```

SQLite 只作为 Repository Adapter 注入，Core、Agent 与 Analyzer 不直接依赖数据库。

## Installation

需要 Python 3.11+ 与 Node.js 22：

```bash
python -m pip install -e ".[test,binary-analysis,report-export]"
npm ci
```

复制 `.env.example` 为本地 `.env` 后可调整 Profile。不要提交真实密钥。
当前 LLM Router 支持已实现的 Provider 配置；默认 `mock` 不需要 API Key。

## LLM Providers

当前统一 `BaseLLM` Adapter 已支持：

- `deepseek`：默认 `https://api.deepseek.com` + `deepseek-v4-flash`；
- `glm`：默认 `https://open.bigmodel.cn/api/paas/v4` + `glm-5.2`；
- `kimi`：默认 `https://api.moonshot.cn/v1` + `kimi-k2.6`；
- `mock`：CI 与无密钥环境使用的确定性实现。

端点和模型名均可由 `.env` 覆盖。Planner 只接收模型返回的公开 JSON 摘要，模型不能直接修改 Task 状态、确认漏洞或绕过 Supervisor。未配置所选 Provider 的 Key 时启动会明确失败，不会静默切换或伪造结果。

配置真实 Key 后可执行三个 Single LLM vs Evidence-First Full 的同样本比较（再次运行会产生 API 费用）：

```bash
python -m experiments.run_llm_comparison --manifest benchmarks/manifest.json --providers deepseek glm kimi --output-dir artifacts/experiments/llm-comparison
```

2026-09-11 已在当前 20 样本 manifest 上完成 DeepSeek V4 Flash、GLM-5.2 与 Kimi K2.6 的 60 次真实分类调用，每个接口均 20/20 次成功返回 usage。DeepSeek 为 5,248 Token、按调用时段的 weekday-peak 费率估算 0.002317218 USD；GLM 为 5,803 Token、估算 0.069904 CNY；Kimi 为 4,696 Token（缓存输入 3,088）、估算 0.0347383 CNY。三者分类 F1 均为 1.0、Evidence Chain Coverage 均为 0，VulnAgent Full 的分类 F1 为 1.0、Evidence Chain Coverage 为 1.0。Kimi Adapter 还封装了 K2.6 固定 `temperature=0.6` 和低 RPM 账户的有界请求节流/429 退避。费用使用 `run_manifest.json` 中带日期、来源、费率档位和币种的估算，不同币种不会相加。

参考：[DeepSeek Chat Completions](https://api-docs.deepseek.com/api/create-chat-completion/)、[智谱对话补全](https://docs.bigmodel.cn/api-reference/%E6%A8%A1%E5%9E%8B-api/%E5%AF%B9%E8%AF%9D%E8%A1%A5%E5%85%A8) 与 [Kimi Chat Completions](https://platform.kimi.com/docs/api/chat)。

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

一键编译自研样本并通过正式运行时生成 JSON 证据报告：

```bash
python scripts/demo_binary_v03.py
```

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

执行时间和输出有界；Windows 默认后端使用 Job Object 强制活动进程数、Job CPU
时间、进程/Job 内存和关闭时终止进程树，并在运行证据中记录内核限制与计量值。
Job Object 不能强制断网或提供文件系统白名单，因此这两项会显式标为 unsupported；
非 Windows 的 subprocess 后端也不会把策略声明冒充操作系统隔离。动态执行仍只允许
自研且可审计的本地靶标。真实异常退出转换为
`CRASH_LOG` Evidence，再交由 Verification 判定。禁止用于互联网、未知程序、
未授权目标或自动利用。

Source Audit 的结构化风险类型会被转换成非 Exploit 的边界探针，并与通用随机变异共享同一固定预算：

```bash
python scripts/demo_fuzz_v03.py
```

V0.4 推荐使用单一入口同时生成 Source、Binary、授权 Fuzz 现场结果和实验快照索引；它不会发起任何外部 LLM 调用：

```powershell
.\.venv\Scripts\python.exe scripts\demo_v04.py --output-dir artifacts\demos\v04
```

完成后先打开 `artifacts/demos/v04/summary.md`。脚本会按 manifest SHA-256 校验 LLM、ELF 与 Part 6B 快照是否为 `current`，不匹配的付费 LLM 结果标为 `frozen_prior_scope`，避免把不同实验批次混为一谈。该命令同时生成 Source、Binary、Fuzz 的离线 HTML 与可打印 PDF；轻量环境未安装 ReportLab 时可添加 `--skip-pdf`。只想演示静态路径时可添加 `--skip-fuzz`。

受保护二进制的 2+2 严格准入和 Part 6B 静态实测：

```powershell
.\.venv\Scripts\python.exe -m experiments.audit_protected_samples --manifest benchmarks\packed\manifest.json --manifest benchmarks\obfuscated\manifest.json --output-dir artifacts\experiments\protected-readiness --require-complete
.\.venv\Scripts\python.exe -m experiments.run_protected_benchmark --manifest benchmarks\packed\manifest.json --manifest benchmarks\obfuscated\manifest.json --output-dir artifacts\experiments\protected-benchmark --allow-transform
```

真实 ELF-A 使用官方 Zig 0.16.0 交叉编译 6 个授权 Fixture 的 3 个 Profile，共 18 条只读分析记录：

```powershell
.\.venv\Scripts\python.exe -m experiments.run_elf_benchmark --manifest benchmarks\elf\manifest.json --output-dir artifacts\experiments\elf-benchmark --compiler tools\zig\zig-x86_64-windows-0.16.0\zig.exe
```

两个实验均不执行目标。受保护挑战没有漏洞 Ground Truth，因此只报告准入、静态信号、工具变换、Evidence/Verification/Report 闭环，不报告虚构的漏洞 Precision/Recall。

已有结构化 JSON 也可单独导出，不重新运行分析：

```powershell
.\.venv\Scripts\python.exe scripts\export_report_html.py --input artifacts\demos\v04\source.json --output artifacts\demos\v04\source.html
.\.venv\Scripts\python.exe scripts\export_report_pdf.py --input artifacts\demos\v04\source.json --output artifacts\demos\v04\source.pdf
```

## Reproducible Evaluation

当前包含 20 个 Source 样本、14 个本地编译 Binary 样本和 10 次配对 Fuzz 消融试验。Source/Binary 清单按 `family_id` 组织漏洞与安全反例，并标记 basic/hard 难度。复现命令、指标与适用边界见 `docs/04_evaluation/reproducible_evaluation.md`。

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
- Fuzz 演示仅限本地、明确授权、受控目标；Windows Job Object 已强制进程树和
  CPU/内存/进程数边界，但网络与文件系统隔离尚未实现，不等同于完整虚拟机隔离。
- 真实 LLM Provider 需要对应 API Key；缺失时应使用 `mock` 或明确不可用。
- 默认存储仍为内存；启用 SQLite 后可恢复 Task、Evidence 和最终 AnalysisContext。运行中的 Agent checkpoint 与 EventBus 历史仍不做跨进程恢复。

更完整的边界说明见 `docs/01_architecture/v0.3_integration.md`。
