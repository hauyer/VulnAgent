# Source Parser（成员 2）

输入 `ProjectInput`，输出 `SourceAnalysisResult`。负责项目导入、语言、AST、符号、依赖和基础调用图。只允许依赖 Contracts、工具接口和 Utils；禁止判断漏洞、调用 Verification/Fuzz、具体 LLM 厂商或生成确认漏洞。测试入口：`pytest tests/contracts tests/source_parser`（目录存在时）。
