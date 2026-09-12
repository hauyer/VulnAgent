# Source Parser（成员 2）

输入 `ProjectInput`，输出 `SourceAnalysisResult`。负责**项目导入、语言识别、目录解析、AST/函数/类索引、依赖和基础调用图**。只允许依赖 Contracts、工具接口和 Utils；禁止判断漏洞、调用 Verification/Fuzz、具体 LLM 厂商或生成确认漏洞。测试入口：`pytest tests/contracts tests/source_parser`。

组件能力总览（P2 交付面）：

| 能力 | 实现 | 说明 |
| --- | --- | --- |
| 项目导入 | `ProjectImporter` | 本地目录/文件直用；`.zip` 安全解压（防 zip-slip、限大小）；Git 仓库 URL 浅克隆（默认拒绝，需 `metadata["allow_git_clone"]=true`） |
| 语言识别 | `languages.py` / `SourceProjectParser` | 13 种语言注册表、项目语言集合与计数 |
| 目录解析/扫描 | `SourceProjectParser` | 忽略规则、大小限额、编码/语法/遍历错误容错 |
| Python 结构解析 | `python_parser.py` | 函数/类/方法符号（继承、装饰器、参数、注解）、import 位置、依赖、调用图解析、入口点 |
| C/C++/Go 结构解析 | `native_parser.py` | 使用本地 Tree-sitter 语法包构建归一化 AST、函数级语句 CFG、调用与数据流事实；运行时不下载语法 |
| 统一输出 | 公共 `SourceParser` Protocol | `SourceAnalysisResult`（frozen Contract，未修改） |

## 项目导入（ProjectImporter）

- 本地目录/单文件：直接使用（`origin_type="path"`），检测到 `.git` 时 `vcs="git"`。
- `.zip`：解压到 `destination`（未提供时创建托管临时目录，可 `importer.cleanup()` 清理）；拒绝 `..`/绝对路径逃逸成员（zip-slip），可选 `max_extract_bytes` 限制。
- Git 仓库 URL（`https/http/git/ssh/file` 等）：默认**拒绝**克隆，需 `ProjectInput.metadata["allow_git_clone"]=true`；`--depth 1` 浅克隆、禁用终端凭据提示、超时可控（`git_clone_timeout_seconds`）。
- 导入只物化输入，不执行任何项目代码。

## 解析器

`SourceProjectParser`（V0.3 项目级真实解析器，实现 `SourceParser` Protocol）：

- 以项目目录或单个源码文件为输入，统一扫描并过滤虚拟环境、依赖目录、构建产物和工具缓存目录；
- 通过扩展名识别项目中的真实语言集合，写入 `SourceAnalysisResult.languages`（小写规范 id，如 `["c", "python"]`），并在 `metadata.language_counts` 给出每种语言的文件数；
- 对 Python（`.py`/`.pyi`）以及 C/C++/Go 做结构解析；其余已识别语言保留在 `files` 索引中，并在 `metadata.unsupported_languages` 明确标注“已识别但未结构解析”，避免下游把“不支持”误判为“空项目”；
- C/C++/Go 的归一化 AST、函数级 CFG 和审计事实放在 `metadata.native_analysis.files` 中，不修改冻结的 `SourceAnalysisResult` 公共字段；
- 大文件（默认 > `max_file_bytes`，可由 `ProjectInput.metadata.max_file_bytes` 调整）跳过并计数，其它无源码扩展名的文件计入 `metadata.other_file_count`；
- 单文件语法/读取错误写入 `metadata.parse_errors`，不影响其它文件；路径不存在返回带 `PathNotFoundError` 的空结果而非抛异常。

`PythonSourceParser` 是单语言（Python）解析器，保留为兼容入口；其内部按文件解析逻辑已抽为 `python_parser.parse_python_file`，供项目级解析器复用。二者对同一 Python 项目产出**一致的** `call_graph` 语义与 import 元数据。

`MockSourceParser` 继续保留；`v03-source` Profile 已在 composition root 显式接入真实解析器。

### C/C++/Go 归一化 IR

`metadata.native_analysis.files[相对路径]` 包含：

- `ast.nodes`：有界的具名 Tree-sitter 节点（类型、文本、行列、父节点）；
- `functions[]`：函数/方法、参数、调用目标和源码范围；
- `functions[].cfg`：`entry/exit`、普通语句、条件、循环、汇合节点及 `next/true/false/back/return` 边；
- `functions[].facts`：调用、赋值、条件、数组声明和数组/切片索引事实；
- `dependencies` 与 `has_syntax_error`：头文件/Go import 和容错语法诊断。

该 IR 只来自本地源码字节。解析器不运行预处理器、编译器、项目脚本或目标程序，也不访问网络。当前 CFG 是函数内、语句级近似；宏展开、模板实例化、完整类型推导与动态派发不在本框架范围内。

## 语言约定

- `languages.py` 维护可识别语言注册表（Python、C、C++、Java、JavaScript、TypeScript、Go、Rust、PHP、Ruby、C#、Kotlin、Swift）。
- 语言 id 统一小写（`python`/`c`/`cpp`/...）；`SourceProjectParser` 的 `languages` 字段即小写 id 列表。
- 注意：`PythonSourceParser`（兼容入口）历史语义为显示名 `["Python"]`，二者不可混读；V0.3 及以后的新集成统一使用 `SourceProjectParser`。

## import 元数据（审计可消费）

`SourceAnalysisResult.metadata["imports"]` 是 `{文件(相对路径): [条目...]}`。每条含：

- `name`：绑定的顶层名称（`from x import y` 为 `y`，`import x` 为 `x`）；
- `asname`：别名（无则 `None`）；
- `module`：被导入模块名（不含相对点号；相对导入为 `""`）；
- `level`：相对导入层级（0 = 绝对导入）；
- `is_from` / `is_relative`：是否为 `from ... import` / 相对导入；
- `line` / `column`：语句位置。

`SourceAnalysisResult.dependencies`（字符串列表）保持向后兼容。

## 符号结构索引

`symbols` 每条（函数/方法/类）除 `name/qualified_name/kind/file/line/end_line/column/is_async` 外，另含：

- 函数/方法：`decorators`（装饰器源码文本列表，如 `["route('/run')"]`）、`parameters`（每个参数：`name`/`kind`（positional_or_keyword|positional_only|vararg|keyword_only|kwarg）/`has_default`/`annotation`，按源码顺序）、`return_annotation`；
- 类：`bases`（基类表达式列表）、`decorators`。

`metadata["entry_points"]`：含顶层 `if __name__ == "__main__"` 保护的文件与行号列表（`[{file, line}]`），可辅助定位程序入口/不可信输入来源。

## call_graph 解析语义

`call_graph`：调用方（模块限定名）→ 被调目标列表；**best-effort 解析到项目内定义符号的 qualified name**（`python_resolver.py`）：

- `self.x`/`cls.x` → 类内方法定义（`main.Service.run` → `main.Service.finish`）；
- 裸名 → 同模块模块级定义或 `from x import y` 导入且项目内可找到的定义（`y` → `x.y`）；
- 别名点号调用（`import a.b as ab; ab.f()`）→ 用别名目标模块替换；
- **解析不到**的外部/动态调用保留原始语法名（如 `os.getcwd`、`subprocess.run`）；
- 无调用的函数保留空列表键。

已知限制：相对导入 base 依据模块名近似推导；`import a.b`（无别名）不建绑定（全路径调用按 def 精确匹配）；通过变量/动态派发的调用不解析。解析只会在项目内确证定义存在时才改写，不发明调用边。
