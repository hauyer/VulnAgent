# Source Parser（成员 2）

输入 `ProjectInput`，输出 `SourceAnalysisResult`。负责项目导入、语言、AST、符号、依赖和基础调用图。只允许依赖 Contracts、工具接口和 Utils；禁止判断漏洞、调用 Verification/Fuzz、具体 LLM 厂商或生成确认漏洞。测试入口：`pytest tests/contracts tests/source_parser`。

## 解析器

`SourceProjectParser`（V0.3 项目级真实解析器，实现 `SourceParser` Protocol）：

- 以项目目录或单个源码文件为输入，统一扫描并过滤虚拟环境、依赖目录、构建产物和工具缓存目录；
- 通过扩展名识别项目中的真实语言集合，写入 `SourceAnalysisResult.languages`（小写规范 id，如 `["c", "python"]`），并在 `metadata.language_counts` 给出每种语言的文件数；
- 当前仅对 Python（`.py`/`.pyi`）做结构解析（符号/依赖/基础调用图）；其余已识别语言保留在 `files` 索引中，并在 `metadata.unsupported_languages` 明确标注“已识别但未结构解析”，避免下游把“不支持”误判为“空项目”；
- 大文件（默认 > `max_file_bytes`，可由 `ProjectInput.metadata.max_file_bytes` 调整）跳过并计数，其它无源码扩展名的文件计入 `metadata.other_file_count`；
- 单文件语法/读取错误写入 `metadata.parse_errors`，不影响其它文件；路径不存在返回带 `PathNotFoundError` 的空结果而非抛异常。

`PythonSourceParser` 是单语言（Python）解析器，保留为兼容入口；其内部按文件解析逻辑已抽为 `python_parser.parse_python_file`，供项目级解析器复用。

`MockSourceParser` 继续保留，现有集成链路可在 composition root 明确切换后再采用真实解析器。

## 语言约定

- `languages.py` 维护可识别语言注册表（Python、C、C++、Java、JavaScript、TypeScript、Go、Rust、PHP、Ruby、C#、Kotlin、Swift）。
- 语言 id 统一小写（`python`/`c`/`cpp`/...）；`SourceProjectParser` 的 `languages` 字段即小写 id 列表。
- 注意：`PythonSourceParser`（兼容入口）历史语义为显示名 `["Python"]`，二者不可混读；V0.3 及以后的新集成统一使用 `SourceProjectParser`。
