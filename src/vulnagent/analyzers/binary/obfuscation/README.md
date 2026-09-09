# Binary Obfuscation（成员 5）

只消费 `BinaryAnalysisResult` 并输出结构化特征。不得重新执行基础解析，不得直接实例化 Ghidra、UPX 或 Reverse 具体类。测试入口：`pytest tests/contracts tests/obfuscation`（目录存在时）。

## 本地学习工具（仅手工分析与实验，不 import 进本模块）

- Python 依赖（可选组）：`pip install -e ".[binary-analysis]"`，含 pefile / pyelftools / capstone / yara-python / unicorn。
- 便携二进制工具：`python scripts/fetch_binary_tools.py` 下载 UPX 5.2.1 与 radare2 6.2.2 到 `tools/`（已 gitignore），仅用于壳检测、脱壳、反汇编等手工分析；模块代码只消费 `BinaryAnalysisResult`。
- VS Code 插件：`ms-vscode.hexeditor`、`13xforever.language-x86-64-assembly`（见 `.vscode/extensions.json`）。
