# Report（成员 9）

只消费 Task、VulnerabilityCandidate、VerificationResult 和 Evidence，输出 `ReportResult`。禁止读取 Analyzer、Fuzzer 或 Agent 内部对象。

报告包含任务概览、状态汇总、每个 Finding 的 Verification 和关联 Evidence、轻量 Evidence Graph，以及缺失证据和未复核 Finding 的限制说明。报告由结构化数据生成，不能将模型文本当作确认依据。

测试入口：`pytest tests/contracts tests/evidence tests/report`（目录存在时）。
