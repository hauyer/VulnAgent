# Verification（成员 7）

输入 `VulnerabilityCandidate` 与 `VerificationContext`，输出 `VerificationResult`。这是确认或拒绝漏洞的唯一边界。不得反向依赖 Source/Fuzz 具体实现。测试入口：`pytest tests/contracts tests/verification`（目录存在时）。
