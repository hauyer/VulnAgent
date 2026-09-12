# 静态源码审计引擎核心框架

> 用途：本地授权、防御性代码审计。该模块只读取源码并输出“候选漏洞”，不编译或执行目标、不访问外网，也不生成 Exploit、PoC 或利用步骤。

## 1. 目录结构

```text
src/vulnagent/analyzers/source/
├── parser/
│   ├── languages.py              # 扩展名与语言能力注册表
│   ├── source_project_parser.py  # 项目扫描、统一结果组装
│   ├── python_parser.py          # Python AST/符号/调用图
│   ├── native_parser.py          # C/C++/Go Tree-sitter AST、CFG、事实提取
│   └── native_models.py          # 内部归一化 AST/CFG/函数 IR
└── audit/
    ├── auditor.py                # Python AST 污点规则
    ├── native_auditor.py         # C/C++/Go 污点传播与缺陷规则
    └── rules.py                  # 规则编号、CWE、等级、置信度

tests/
├── source_parser/test_native_parser.py
└── source_audit/test_native_auditor.py
```

## 2. 核心流程

```text
ProjectInput
    │
    ▼
SourceProjectParser ── 文件清单、语言、大小限制、路径边界
    │
    ├── Python ast
    └── 本地 Tree-sitter（C / C++ / Go）
            │
            ├── 归一化 AST
            ├── 函数级语句 CFG
            └── call / assignment / condition / array / index 事实
    │
    ▼
SourceAnalysisResult（公共契约保持不变；native IR 放 metadata）
    │
    ▼
MultiLanguageSourceAuditor
    ├── PythonSourceAuditor
    └── NativeSourceAuditor
            │
            ├── 参数、网络输入 → taint source
            ├── 局部赋值 → taint propagation
            ├── 比较 / len / sizeof → guard signal
            └── copy / allocation / index → sink rule
    │
    ▼
VulnerabilityCandidate（固定为 CANDIDATE）
    │
    └── location + rule_id + snippet + taint_path + limitations
```

## 3. 核心类与接口

| 类/接口 | 输入 | 输出 | 职责 |
| --- | --- | --- | --- |
| `SourceParser.analyze` | `ProjectInput` | `SourceAnalysisResult` | 公共解析协议 |
| `SourceProjectParser` | 本地目录或单文件 | 项目统一结构 | 扫描、语言路由、聚合 |
| `NativeSourceParser.parse_file` | 路径、相对路径、语言 | `NativeFileAnalysis` | 构建 C/C++/Go AST、CFG 和事实 |
| `SourceAuditor.audit` | `SourceAnalysisResult` | `list[VulnerabilityCandidate]` | 公共审计协议 |
| `NativeSourceAuditor` | `metadata.native_analysis` | 原生代码候选 | 污点传播、规则匹配、去重 |
| `MultiLanguageSourceAuditor` | 统一解析结果 | 多语言候选集合 | 组合 Python 与原生审计器 |

公共 Schema 没有新增或改字段。内部 `NativeFileAnalysis/NativeFunctionIR` 先序列化到 `metadata.native_analysis`，既保留 AST/CFG 证据，也避免破坏已有 API。

## 4. 核心数据结构

```text
NativeFileAnalysis
├── language
├── ast.nodes[]
│   └── node_id, node_type, text, line_start, line_end, column, parent_id
├── functions[]
│   ├── name, qualified_name, parameters, line_start, line_end
│   ├── cfg.nodes[] / cfg.edges[]
│   ├── facts[]
│   └── callees[]
├── dependencies[]
└── has_syntax_error

VulnerabilityCandidate
├── vulnerability_type / cwe_id / severity / confidence
├── location.file_path / function_name / line_start / line_end
└── metadata
    ├── rule_id / language / sink / snippet
    ├── source_kinds / taint_path
    ├── guard_observed
    └── limitations
```

## 5. 污点分析伪代码

```python
for function in parsed_file.functions:
    state = {parameter: taint("api_parameter") for parameter in function.parameters}

    for fact in source_order(function.facts):
        if fact is input_call:
            state[fact.output] = taint("network_or_api_input")

        if fact is assignment:
            state[fact.target] = merge(state[name] for name in fact.rhs_identifiers)

        if fact is condition:
            remember_guard(fact.identifiers, fact.expression)

        if fact is dangerous_copy:
            check_unbounded_function_or_controllable_length(fact, state, guards)

        if fact is allocation and fact.size_has_arithmetic:
            check_tainted_size_without_range_or_overflow_guard(fact, state, guards)

        if fact is array_or_slice_index:
            check_tainted_index_without_range_guard(fact, state, guards)

emit_candidate_only(type, file, line, function, taint_path, severity)
```

## 6. 当前规则边界

- 危险调用：`gets/strcpy/strcat/sprintf/vsprintf` 的无界写入；`memcpy/memmove/strncpy/strncat` 的长度与固定数组不匹配，或长度受污染且未观察到检查。
- 整数溢出/下溢候选：受污染算术表达式进入 `malloc/calloc/realloc/aligned_alloc/new/make` 大小或下标计算，且未观察到范围检查。
- 缓冲区/数组越界候选：固定数组容量与字面量拷贝长度不匹配，或受污染下标未观察到范围检查。
- 输入校验缺失：API 参数或本地解析到的网络/输入数据抵达敏感操作前，没有观察到比较、`len`、`sizeof` 等检查。

本框架是可解释的函数内静态分析基线。它没有完整预处理器、编译器类型系统、跨过程摘要、指针别名和路径可达性证明，因此既可能漏报也可能误报。正确流程是将结果送入统一证据链与独立 Verification；发现阶段不得写入 `CONFIRMED`。

## 7. 安全边界

- 只处理 `SourceProjectParser` 已建立的本地文件清单，并限制单文件大小。
- Tree-sitter 语法以 Python 依赖形式预装；运行时不下载语法或依赖。
- 不调用编译器、构建脚本、调试器、目标程序、系统命令或网络服务。
- 不产生 Payload、PoC、Exploit、权限提升、远程扫描或代码执行验证内容。
- 所有输出仅为带证据和限制说明的防御性候选，默认状态为 `CANDIDATE`。
