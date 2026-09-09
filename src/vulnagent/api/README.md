# Platform API（成员 8）

API 只暴露 Task、Finding、Evidence、VerificationResult、Report 和执行 Trace 等资源，不读取 Analyzer/Fuzzer/Agent 内部对象。Frontend 只能调用这些 API。测试入口：`pytest tests/integration/test_api.py`。
