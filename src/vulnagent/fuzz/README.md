# Dynamic / Fuzz（成员 6）

输入 `FuzzRequest`，输出 `FuzzResult` 和 Evidence。调用方只依赖 `FuzzEngine`。默认 Mock 不执行目标；真实执行必须明确授权并处于沙箱。禁止确认漏洞。测试入口：`pytest tests/contracts tests/fuzz`（目录存在时）。
