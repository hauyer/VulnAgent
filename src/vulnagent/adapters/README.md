# Adapters

第三方工具只能在本边界实现。Adapter 将外部工具输出转换为 `vulnagent.contracts` 中的结构，不参与 Agent 调度、不修改 Task/Finding 状态、不定义新的公共结果模型。

工具目录按集成拆分为 Semgrep、Ghidra、radare2、UPX 和 LLM。对应能力 Owner 独立维护自己的 Adapter，避免共同编辑聚合文件。
