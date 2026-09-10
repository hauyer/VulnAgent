# Report（成员 9）

只消费 Task、VulnerabilityCandidate、VerificationResult 和 Evidence，输出 `ReportResult`。禁止读取 Analyzer、Fuzzer 或 Agent 内部对象。测试入口：`pytest tests/contracts tests/report`（目录存在时）。
