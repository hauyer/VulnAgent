# Source Audit（成员 3）

输入 `SourceAnalysisResult`，输出统一 `VulnerabilityCandidate`。只允许依赖 Contracts、LLM 接口和 Adapter 接口；禁止确认漏洞或导入具体 Verification Agent。测试入口：`pytest tests/contracts tests/source_audit`（目录存在时）。
