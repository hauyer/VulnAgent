# Source Parser（成员 2）

输入 `ProjectInput`，输出 `SourceAnalysisResult`。负责项目导入、语言、AST、符号、依赖和基础调用图。只允许依赖 Contracts、工具接口和 Utils；禁止判断漏洞、调用 Verification/Fuzz、具体 LLM 厂商或生成确认漏洞。测试入口：`pytest tests/contracts tests/source_parser`（目录存在时）。

`PythonSourceParser` 是第一条真实源码解析链路。它：

- 扫描项目目录或单个 Python 文件；
- 忽略 `.git`、`.venv`、`venv`、`__pycache__`、`node_modules`、`build` 和 `dist`；
- 使用 Python 标准库 AST 提取函数、类、方法、import 依赖和直接调用；
- 使用“模块限定调用方 → 语法调用名列表”表示基础调用图；
- 将单文件语法或读取错误写入 `metadata.parse_errors`，继续分析其他文件。

`MockSourceParser` 继续保留，现有集成链路可在 composition root 明确切换后再采用真实解析器。
