# VulnAgent V0.6 大模型服务软件代码安全审计升级方案

## 1. 建设目标与合规边界

本升级面向北京邮电大学网络空间安全学院本科《网络空间安全课程设计》中的防御性软件安全审计实验。在 V0.5 已具备 AI 交互风险检测、二进制保护识别和代码还原能力的基础上，V0.6 新增“大模型服务软件代码安全”审计域，使系统能够从服务端源码、控制流和数据流角度发现潜在安全风险。

检测对象必须是本地部署、开源授权且经课程或授权方确认的大模型服务软件及其源码，例如本地 Ollama 服务端、推理引擎组件和课程自建样本。所有测试必须在本地沙箱、低权限、无外网、可重置环境中执行。

系统只允许以下防御性操作：

1. 对 Go、C、C++ 源码进行只读解析，构建 AST、CFG 和污点路径；
2. 使用规则库定位整数边界、内存访问、输入校验、资源管理和访问控制候选风险；
3. 在合格本地沙箱内进行边界值、空值、受限超长字符串和异常类型的健壮性验证；
4. 监控崩溃、异常退出、内存错误、超时和服务不可用；
5. 保存脱敏证据、独立复核结果和修复建议。

系统明确禁止远程扫描、漏洞利用、代码执行类验证、权限提升、敏感数据读取、数据外传，以及生成 PoC、Exploit、攻击载荷或绕过步骤。所有页面和报告统一标注：**仅用于安全审计与防御研究，仅限教学实验使用。**

V0.6 继续采用证据驱动的判定方式：静态规则命中只产生 `CANDIDATE`；CodeAuditAgent 的模型研判只产生辅助 Evidence；动态异常只说明服务在特定无害边界输入下出现健壮性问题；只有独立 VerificationAgent 可以将结果标记为确认、排除或存疑。

## 2. 本轮代码落地范围

| 能力 | 当前实现 | 运行边界 |
|---|---|---|
| 审计分类扩展 | 已新增 `software_code` 审计域，并与原有 AI 交互安全分类并列展示 | 不改变原有提示注入、系统提示词泄露、安全对齐绕过检测 |
| Go/C/C++ 解析 | 已使用 Tree-sitter 构建规范化 AST、函数和函数内 CFG | 只读源码，不编译、不执行目标程序 |
| 污点传播 | 已从 API 参数、网络输入、文件输入和环境输入追踪至拷贝、分配、下标及敏感管理操作 | 以保守候选检测为目标，跨函数复杂别名仍可能不完整 |
| 代码风险规则 | 已覆盖缓冲区越界、整数边界、数组越界、输入校验、空指针、资源泄漏、接口访问控制和配置权限 | 每条命中均需独立复核 |
| 规则库配置 | 已提供 YAML 规则库、JSON Schema 和加载校验 | 规则不包含测试载荷或利用逻辑 |
| CodeAuditAgent | 已接入 Runtime、Supervisor、消息协议与 Evidence | 只做误报分析、可触发性研判、风险建议，无最终定级权限 |
| 动态健壮性核心 | 已实现用例生成、回环探测、进程监控、沙箱证明、脱敏证据和自动重置 | 实际运行必须注入合格 `ResettableSandbox` Adapter，默认关闭 |
| 独立复核 | 已将源码、CFG、污点、规则、动态摘要和智能体摘要提供给 VerificationAgent | VerificationAgent 是唯一漏洞结论权限方 |
| 漏洞卷宗与报告 | 已新增代码安全卷宗和“大模型服务代码安全审计”报告章节 | 不保存原始动态输入和响应正文 |
| 前端升级 | 已新增分类 Tab、代码风险筛选、源码定位、控制流路径、验证日志和统计卡片 | 只展示审计证据和修复建议，不展示攻击内容 |
| API 输入边界 | 软件代码任务要求本地授权、防御性元数据，拒绝 URL、UNC 和网络路径 | 服务应仅监听回环地址 |

特别说明：本仓库已经交付可测试的动态健壮性核心接口和 fail-closed 策略，但课程实验机仍需提供满足隔离条件的 Sandbox Adapter。未配置 Adapter 或沙箱证明不满足要求时，引擎拒绝运行，并在报告中显示“未执行”，不会把“未发生测试”写成“已经安全”。

## 3. 总体架构

```text
本地授权用户
  -> 前端“开源大模型 / 软件代码安全”
  -> FastAPI Task / Upload API
  -> Planner
  -> SourceAnalysisAgent
       -> ProjectImporter（路径、扩展名、文件规模校验）
       -> Tree-sitter Go/C/C++ Parser
       -> AST + 函数内 CFG
       -> MultiLanguageSourceAuditor
            -> 污点传播
            -> 规则匹配
            -> VulnerabilityCandidate + 静态 Evidence
  -> CodeAuditAgent
       -> 上下文语义研判
       -> 误报可能性、可触发性、风险等级建议、修复建议
       -> MODEL_REASONING_SUMMARY
  -> ControlledRobustnessEngine（可选、显式授权、默认关闭）
       -> 无害边界用例
       -> 回环接口探测 + 进程状态监控
       -> RUNTIME_TRACE + 自动重置
  -> VerificationAgent（唯一结论权限）
  -> Reviewer -> ReportAgent
       -> Evidence Chain
       -> 漏洞卷宗
       -> JSON / Markdown / HTML / PDF
```

关键架构约束与 V0.5 保持一致：Agent 不互相直接调用，Supervisor 是唯一编排入口；Capability 由 Composition Root 注入；分析器只依赖公共 Contract；任何模型输出都不能替代可复现的工具证据和独立复核。

三层审计关系如下：

```text
静态源码审计：回答“风险位置在哪里、数据怎样到达敏感操作”
        ↓
动态受控验证：回答“无害边界输入下是否出现稳定性异常”
        ↓
大模型智能体：结合上下文分析误报、条件与修复方向
        ↓
独立 Verification：综合 Evidence ID 给出正式状态
```

## 4. 软件代码风险分类体系

| 大类 | 风险类型 | 统一类型字段 | 主要静态证据 | 建议等级 |
|---|---|---|---|---|
| 内存安全 | 整数溢出/下溢 | `integer_overflow` | 分配大小或下标算术、输入来源、缺失上下界检查 | HIGH |
| 内存安全 | 栈缓冲区越界 | `buffer_overflow` + `risk_subtype=stack_buffer_overflow` | 栈数组容量、拷贝长度、危险函数和污点路径 | HIGH |
| 内存安全 | 堆缓冲区越界 | `buffer_overflow` + `risk_subtype=heap_buffer_overflow` | 堆分配大小、数据拷贝长度及二者关系 | HIGH |
| 内存安全 | 数组下标越界 | `array_out_of_bounds` | 外部可控下标、缺失下界或严格上界保护 | HIGH |
| 输入校验 | 参数校验缺失 | `input_validation_missing` | 类型、长度、符号、范围检查缺失 | MEDIUM |
| 异常处理 | 空指针引用 | `null_pointer_dereference` | 外部指针或对象在解引用前缺少空值检查 | MEDIUM |
| 资源管理 | 资源泄漏 | `resource_leak` | 资源获取与所有退出路径上的释放关系 | MEDIUM |
| 访问控制 | 本地接口访问控制缺失 | `interface_access_control_missing` | 管理入口到敏感操作路径上缺少身份或权限检查 | HIGH |
| 访问控制 | 配置权限校验缺失 | `configuration_authorization_missing` | 配置写操作前缺少认证、授权或管理员角色检查 | HIGH |

“栈溢出”和“堆溢出”对外保留统一的 `buffer_overflow` 公共类型，以兼容原有 Finding Contract；具体内存区域记录在 `metadata.risk_subtype`。整数减法或符号边界风险则通过 `metadata.integer_boundary_kind` 标注可能的 underflow/overflow 方向。

## 5. 静态源码安全审计引擎

### 5.1 代码导入与解析

源码导入支持 `.c`、`.h`、`.cc`、`.cpp`、`.cxx`、`.hpp`、`.hh` 和 `.go`。ProjectImporter 对路径范围、文件数量和大小进行限制；API 对软件代码任务额外要求 `local_authorized=true` 与 `defensive_only=true`，并拒绝 URL、UNC 或其他网络路径。

`NativeSourceParser` 使用 Tree-sitter 获取语法节点，规范化保存节点类型、文本范围、文件位置和函数归属。与仅用正则匹配相比，AST 可以区分函数调用、表达式、条件和下标访问，为后续 CFG 和污点分析提供稳定结构。

### 5.2 控制流图

系统按函数生成 CFG 节点和边，记录入口、普通语句、条件分支、循环和退出关系。发现候选风险后，从函数入口对 CFG 做有界广度优先搜索，生成到达敏感位置的 `cfg_path`。这条路径用于回答“程序经过哪些控制流节点到达风险点”，而不是尝试恢复或执行完整程序。

### 5.3 污点传播

污点源包括 API 参数、网络输入、文件输入和环境输入；敏感汇包括字符串/内存拷贝、内存分配、数组下标、配置修改和本地管理操作。分析器跟踪赋值、参数传递、算术表达式和调用参数，并同时查找是否存在支配敏感操作的长度、范围、符号、空值、认证或授权检查。

```text
外部输入源
  -> 变量赋值/参数传播
  -> 长度、大小或下标计算
  -> 边界/权限 Guard 检查
  -> 拷贝、分配、索引、配置或管理操作
  -> 候选风险 + taint_path + cfg_path
```

### 5.4 候选漏洞结构

| 字段 | 含义 |
|---|---|
| `vulnerability_type` | 统一风险类型 |
| `location` | 文件、起止行、函数 |
| `severity` / `confidence` | 规则给出的初始等级与置信度 |
| `metadata.audit_domain` | 固定为 `software_code` |
| `metadata.rule_id` | 命中的防御性规则 ID |
| `metadata.sink` | 敏感操作名称 |
| `metadata.snippet` | 有界源码片段 |
| `metadata.taint_path` | 从输入源到敏感操作的数据流路径 |
| `metadata.cfg_path` | 从函数入口到候选位置的控制流路径 |
| `metadata.guard_observed` | 是否观察到支配性保护条件 |
| `metadata.risk_subtype` | 栈/堆缓冲区等细分类别 |

当前实现以函数内数据流为主。宏展开、复杂指针别名、模板、反射、动态分派和跨模块调用可能导致漏报或误报，因此静态结果始终以候选身份进入后续研判。

## 6. 防御性规则库与智能体研判

### 6.1 规则库

规则使用 YAML 保存，并由 JSON Schema 校验。每条规则包含 `rule_id`、名称、描述、漏洞类型、CWE、语言、AST 节点条件、调用目标、污点/Guard 条件、风险等级、置信度和修复建议。规则文件禁止包含 PoC、Exploit、攻击载荷或绕过步骤。

当前规则如下：

| 规则 ID | 检测目标 |
|---|---|
| `VA-NATIVE-MEM-001` | 无边界字符串写入，或外部可控且无容量上限的内存拷贝 |
| `VA-NATIVE-INT-001` | 分配大小或下标算术缺少整数边界检查 |
| `VA-NATIVE-BOUNDS-001` | 外部可控数组/切片下标缺少完整上下界检查 |
| `VA-NATIVE-INPUT-001` | 敏感操作前缺少类型、长度、符号或范围校验 |
| `VA-NATIVE-NULL-001` | 指针或对象解引用前缺少 NULL/nil 检查 |
| `VA-NATIVE-RESOURCE-001` | 文件、套接字或堆内存获取后缺少对应释放 |
| `VA-NATIVE-ACCESS-001` | 本地管理接口到敏感操作前缺少访问控制 |
| `VA-NATIVE-CONFIG-001` | 配置修改操作前缺少认证或授权检查 |

危险函数规则关注 `strcpy`、`strcat`、`sprintf`、`vsprintf`、`gets`、`memcpy` 和 `memmove` 等调用。系统不是“看到函数名就直接报漏洞”，而是结合输入是否可控、目标容量、拷贝长度和前置 Guard 共同生成候选。

### 6.2 CodeAuditAgent

CodeAuditAgent 接收静态候选、源码位置、有限代码片段、规则 ID、污点路径、CFG 路径和已观察到的保护条件，输出固定 JSON 结构：

- `review_result`：`likely_true_positive`、`likely_false_positive` 或 `uncertain`；
- `triggerability`：`reachable`、`conditional`、`unreachable` 或 `unknown`；
- `recommended_severity` 与有限置信度；
- 支持事实、反证事实、缺失证据；
- 修复摘要与防御性修复动作；
- `safety.defensive_only=true`。

模型输出经过字段白名单、长度上限和禁止内容过滤。若模型未配置、JSON 不合法、调用异常或出现攻击性内容，Agent 自动回退到确定性的 `uncertain` 研判。它只生成 `MODEL_REASONING_SUMMARY`，不创建已确认 Finding，也不输出模型私有思维链。

## 7. 动态服务健壮性验证引擎

### 7.1 测试用例生成器

`BoundaryCaseGenerator` 根据已知 API 字段约束生成五类无害用例：空值、空字符串、数值边界、受限超长字符串和异常基础类型。用例数量受 `case_limit` 限制，文本长度受 `max_text_length` 限制；原始请求只在单次内存执行过程中存在，不进入报告。

### 7.2 本地接口限制

`LocalServiceProbe` 只接受 `localhost`、`127.0.0.0/8` 或 `::1` 的 HTTP(S) 端点，只允许 POST、PUT、PATCH 等受控请求方式，并拒绝凭据、查询参数、URL Fragment、代理和重定向。单次超时与最大响应读取量均有硬上限。

### 7.3 监控与判定

监控模块只记录以下公开观察类型：

- `normal`：服务正常完成；
- `crash`：进程崩溃；
- `abnormal_exit`：异常退出；
- `memory_error`：受控监控器观察到内存错误；
- `timeout`：请求超过时间上限；
- `service_unavailable`：本地服务不可用。

系统不会根据动态结果尝试进一步利用，也不会读取敏感数据。Evidence 只保存用例类型、字段路径、长度摘要、状态码、耗时和进程状态，不保存原始请求、响应正文或凭据。

### 7.4 沙箱证明与自动重置

`ResettableSandbox.prepare()` 必须返回 `SandboxAttestation`，证明环境同时满足：低权限、外网禁用、只读根文件系统和可销毁。策略还限制内存、CPU、进程数、用例数和字符串长度。任何一项不满足都会 fail closed。

```text
校验本地端点与授权
  -> 校验 SandboxPolicy
  -> prepare() 获取沙箱证明
  -> 生成有限无害用例
  -> 探测 + 进程快照 + 异常分类
  -> 输出脱敏 RUNTIME_TRACE
  -> finally: reset()
```

当前仓库已完成动态核心框架、接口、策略和 Fake Sandbox 单元测试；实际服务动态演示必须由课程实验机提供符合协议的容器、虚拟机或其他可重置 Adapter。严禁为答辩展示在 FastAPI/API 宿主进程直接运行未知目标。

## 8. 多智能体编排与权限分离

软件代码任务的标准路由为：

```text
Planner
  -> SourceAnalysisAgent
  -> CodeAuditAgent
  -> FuzzAgent / Controlled Robustness（仅显式授权且能力可用）
  -> VerificationAgent
  -> ReviewerAgent
  -> ReportAgent
  -> Finish
```

`AgentRoute.CODE_AUDIT` 已加入 Runtime、Supervisor、Orchestrator、生命周期状态和 Agent Registry。CodeAuditAgent 通过 `REQUEST_ANALYSIS` 接收任务，通过 `ANALYSIS_RESULT` 向 Verification 阶段提供辅助证据；消息中保留 Task ID、Finding ID 和 Evidence ID，避免依赖自然语言名称拼接结果。

权限分离如下：

| 角色 | 输入 | 输出 | 权限限制 |
|---|---|---|---|
| Planner | Task 与 Capability | 有界执行计划 | 不直接扫描或确认漏洞 |
| SourceAnalysisAgent | 本地源码 | 候选与静态 Evidence | 只能创建 `CANDIDATE` |
| CodeAuditAgent | 候选与上下文 | 模型研判摘要 | 无结论权、无动态调度权 |
| Controlled Robustness | 显式授权、本地端点、沙箱 | 脱敏运行摘要 | 不执行代码执行、提权或数据读取验证 |
| VerificationAgent | 候选和完整 Evidence | 确认、排除或存疑状态 | 唯一正式结论权限方 |
| ReviewerAgent | 复核结果 | 完整性检查 | 不替代原始工具证据 |
| ReportAgent | 公共 Contract | 卷宗与报告 | 不重新分析目标、不展示载荷 |

路由具有最大步数、单路由重复次数和安全回退限制。Agent 执行失败时保留类型化 Evidence，并优先生成可解释报告，而不是无限重试或绕过安全边界。

## 9. Evidence 链、漏洞卷宗与报告

每条软件代码风险按 Finding ID 聚合同一条证据链：

```text
源码定位
  -> AST/CFG 控制流路径
  -> 污点传播路径
  -> 候选规则及初始等级
  -> 动态健壮性摘要（可选，未运行时明确标注）
  -> CodeAuditAgent 语义研判
  -> VerificationAgent 独立复核
  -> 修复建议与最终卷宗
```

专项证据结构包括：

| 阶段 | Evidence 类型/来源 | 关键字段 |
|---|---|---|
| 源码定位 | `source_analysis` | 文件、行号、函数、有限代码片段 |
| 静态结构 | `source_analysis` | CFG 路径、污点路径、Guard 状态 |
| 规则匹配 | `TOOL_RESULT` | 规则 ID、风险类型、置信度、修复建议 |
| 动态验证 | `RUNTIME_TRACE` | 用例类别、异常类别、耗时、进程状态、重置结果 |
| 智能体研判 | `MODEL_REASONING_SUMMARY` | 误报可能性、可触发性、反证与缺失证据 |
| 独立复核 | `verification` | 引用 Evidence ID、状态、置信度和依据 |

`software_code_security.dossiers[]` 为每条风险保存漏洞类型、风险等级、源码位置、控制流路径、污点路径、静态证据、动态验证结果、智能体研判、独立复核和修复建议。其结构由 `configs/vulnerability_dossier.schema.json` 约束。

`StructuredReportGenerator` 新增“大模型服务代码安全审计”章节，展示代码风险总数、类型分布、风险等级分布、典型卷宗和 Evidence Chain。React 页面、JSON、Markdown、离线 HTML 和 PDF 消费同一份结构化数据，避免不同出口出现互相矛盾的结论。

## 10. 前端升级

“开源大模型安全审计”入口新增两个分类 Tab：

- **AI 交互安全**：保留提示注入、系统提示词泄露和安全对齐绕过；
- **软件代码安全**：选择本地 Go/C/C++ 文件或项目路径，确认本地教学授权后启动源码审计。

“漏洞卷宗”支持按 AI/代码审计域和具体风险类型筛选。代码风险详情新增：

- 源码定位：文件、行号、函数和有限上下文；
- 控制流路径：从函数入口到候选位置的 CFG 节点；
- 数据流/污点路径：输入源到敏感操作的传播关系；
- 验证日志：仅展示异常分类、耗时和重置状态；
- 修复建议：边界检查、资源管理或最小权限加固方向。

首页统计面板增加软件代码风险数量和风险等级分布；审计报告页增加“大模型服务代码安全审计”章节。前端不展示 Payload、原始请求、原始响应或任何攻击性实现。

## 11. 关键代码索引

| 模块 | 文件 |
|---|---|
| Go/C/C++ AST/CFG 模型 | `src/vulnagent/analyzers/source/parser/native_models.py` |
| Tree-sitter 原生语言解析 | `src/vulnagent/analyzers/source/parser/native_parser.py` |
| 项目源码解析入口 | `src/vulnagent/analyzers/source/parser/source_project_parser.py` |
| 污点传播与规则检测 | `src/vulnagent/analyzers/source/audit/native_auditor.py` |
| 规则库加载校验 | `src/vulnagent/analyzers/source/audit/rule_library.py` |
| YAML 规则库 | `configs/source_audit_rules.yaml` |
| 规则 Schema | `configs/source_audit_rules.schema.json` |
| Agent 研判提示词 | `configs/prompts/code_audit_agent_zh.txt` |
| CodeAuditAgent | `src/vulnagent/agents/code_audit_agent.py` |
| Agent 编排 | `src/vulnagent/agent_runtime/supervisor.py`、`runtime.py` |
| 动态用例与模型 | `src/vulnagent/dynamic_validation/generator.py`、`models.py` |
| 动态接口与引擎 | `src/vulnagent/dynamic_validation/interfaces.py`、`engine.py` |
| 回环探测与监控 | `src/vulnagent/dynamic_validation/probe.py`、`monitor.py` |
| 动态脱敏证据 | `src/vulnagent/dynamic_validation/evidence.py` |
| 动态配置示例 | `configs/dynamic_robustness.example.yaml` |
| 漏洞卷宗 Schema | `configs/vulnerability_dossier.schema.json` |
| API 边界 | `src/vulnagent/api/routes/tasks.py`、`uploads.py` |
| 报告生成 | `src/vulnagent/report/generator.py`、`html.py`、`pdf.py` |
| 前端入口与卷宗 | `src/components/TestLabView.tsx`、`VulnerabilitiesView.tsx` |
| 前端统计与报告 | `src/components/DashboardView.tsx`、`ReportView.tsx` |

## 12. 验收与指标设计

建议课程样本同时保存安全版本与含教学缺陷版本，并记录源码版本、构建信息和 SHA-256。动态实验还需记录沙箱镜像 ID、资源配额和重置证明。

推荐指标：

- 解析成功率：成功构建 AST/CFG 的 Go/C/C++ 文件数 / 合法输入文件数；
- 规则覆盖率：被至少一条规则覆盖的目标风险类型数 / 计划风险类型数；
- 定位准确率：文件、函数和行号与人工标签一致的候选数 / 候选总数；
- 污点路径完整率：能够给出输入源到敏感操作路径的候选数 / 需要污点分析的候选数；
- Precision、Recall、F1：以人工标注的本地教学样本为 Ground Truth；
- 误报过滤率：经独立复核排除的误报数 / 静态候选误报数；
- 动态异常复现率：在合格沙箱内稳定复现的无害异常数 / 尝试验证数；
- 证据完整率：具备源码、规则、路径、研判、复核和修复建议的卷宗数 / 代码风险卷宗总数；
- 性能：单项目解析 P50/P95 耗时和峰值内存。

不能把“规则命中”当作“漏洞确认”，也不能把“动态验证未启用”写成“未发现异常”。验收必须同时检查 Finding 状态、Evidence ID 关联、脱敏字段、合规标注和报告各出口的一致性。

## 13. 运行与测试

```powershell
python -m pip install -e ".[test,binary-analysis,report-export]"
npm ci
$env:VULNAGENT_PROFILE="v03-source"
python -m uvicorn vulnagent.api.app:app --host 127.0.0.1 --port 8000
```

另开终端启动前端：

```powershell
npm run dev
```

防御性验证命令：

```powershell
python -m pytest tests/source_audit tests/dynamic_validation tests/report -q
npm run lint
npm run build
```

本轮最近一次仓库全量验证结果为 `540 passed`，前端 Lint 与生产构建均通过。动态单元测试使用 Fake Probe、Fake Monitor 和 Fake Sandbox，不会发送真实网络请求或运行未知目标。

### 推荐答辩演示流程

1. 在“开源大模型”页面切换到“软件代码安全”；
2. 选择课程自建的本地 Go/C/C++ 教学样本并勾选授权确认；
3. 展示 AST/CFG 解析、规则候选和 CodeAuditAgent 研判过程；
4. 打开某条漏洞卷宗，依次展示源码定位、污点路径、控制流路径和规则依据；
5. 若课程沙箱 Adapter 已配置，再展示无害边界测试与自动重置日志；未配置时主动说明 `not configured` 边界；
6. 展示 VerificationAgent 的独立结论和“大模型服务代码安全审计”报告章节；
7. 最后强调系统只输出证据和修复建议，不输出攻击性实现。

## 14. 答辩讲解话术

### 回应“原系统审计维度单一”

“原系统主要看模型交互层的提示注入、信息泄露和安全对齐问题。V0.6 新增了软件代码安全域，能够直接审计大模型服务端的 Go、C、C++ 源码，覆盖内存安全、输入校验、资源管理和访问控制，因此审计对象从‘模型回答是否安全’扩展到了‘承载模型的服务软件是否安全’。”

### 回应“静态审计是怎么实现的”

“系统先用 Tree-sitter 把 Go、C、C++ 解析成 AST，再按函数构建 CFG。随后从 API 参数、网络输入等污点源追踪到拷贝、分配、数组下标和管理操作，同时检查路径上有没有长度、范围、空值或权限 Guard，最后输出文件、行号、函数、污点路径和控制流路径。”

### 回应“为什么不是简单正则匹配”

“函数名只是一条信号，我们还会看参数的数据来源、长度计算、目标容量和前置条件。比如遇到内存拷贝时，系统会判断长度是否受外部输入影响、是否存在支配该操作的上限检查，因此结果是一条可解释的候选证据链，而不是看到关键词就直接报漏洞。”

### 回应“大模型 Agent 起什么作用”

“CodeAuditAgent 读取静态候选和上下文，判断更像真实风险、误报还是证据不足，并给出可触发条件、等级建议和修复方向。但模型没有漏洞确认权限，最终状态必须由 VerificationAgent 引用具体 Evidence ID 独立给出，这样可以降低模型幻觉对审计结论的影响。”

### 回应“动态验证是否安全”

“动态部分只做本地服务健壮性测试，输入限定为空值、边界值、受限超长字符串和异常基础类型，只观察崩溃、异常退出、内存错误、超时和不可用。引擎只允许回环地址，并要求沙箱证明低权限、无外网、只读和可重置，任何条件不满足就拒绝运行。”

### 回应“动态功能现在完成到什么程度”

“用例生成、端点限制、监控分类、沙箱证明、脱敏 Evidence 和 finally 自动重置的核心框架已经完成，也有 Fake Sandbox 单元测试。实际运行仍需要课程实验机注入合格的 ResettableSandbox Adapter；未配置时会明确显示未执行，不会在宿主机冒充完成动态验证。”

### 回应“多智能体是否只是页面展示”

“CodeAuditAgent 已加入真实 AgentRoute 和 Supervisor 调度。SourceAnalysisAgent 生成静态候选，CodeAuditAgent 生成辅助研判，动态模块在显式授权时提供运行摘要，VerificationAgent 是唯一结论角色，Reviewer 和 ReportAgent 再完成质量检查和卷宗输出。各阶段通过 Task ID、Finding ID 和 Evidence ID 关联，不是写死的一条界面动画。”

### 强调 V0.6 技术亮点

“V0.6 的亮点不是简单增加几条危险函数规则，而是建立了 AST、CFG、污点分析、规则检测、模型研判、受控动态观察、独立复核和结构化报告组成的闭环。每条结论都能回到源码位置、路径和工具证据，同时模型和动态执行都受到权限边界约束。”

### 主动说明限制

“当前污点传播以函数内分析为主，对复杂宏、指针别名、模板和跨模块动态调用仍可能不完整；动态验证也依赖独立沙箱 Adapter。因此系统会保留 `candidate` 或 `uncertain` 状态，不用演示效果替代真实证据。我们的目标是可解释、可复现、合规的防御性审计，而不是输出攻击能力。”
