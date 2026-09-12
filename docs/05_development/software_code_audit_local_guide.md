# 软件代码安全审计：配置与本地演示

> 仅用于安全审计与防御研究，仅限教学实验使用。所有操作必须在本地沙箱、低权限、无外网、可重置环境中完成。

## 安装与启动

```powershell
python -m pip install -e ".[test,binary-analysis,report-export]"
npm ci
$env:VULNAGENT_PROFILE="v03-source"
python -m uvicorn vulnagent.api.app:app --host 127.0.0.1 --port 8000
```

另开终端运行前端：

```powershell
npm run dev
```

不要将服务监听到公网网卡。动态配置示例位于 `configs/dynamic_robustness.example.yaml`；示例只说明 Adapter 必须满足的证明条件，不会自动在宿主机执行目标程序。

## 前端演示步骤

1. 打开“测试实验室”并选择“开源大模型”。
2. 切换到“软件代码安全”Tab。
3. 选择本地授权的 `.c/.h/.cc/.cpp/.cxx/.hpp/.go` 文件，或填写项目内源码路径。
4. 确认本地教学授权后点击“开始代码安全审计”。
5. 系统依次运行源码解析、静态规则、代码审计 Agent、独立复核与报告生成，并自动打开漏洞卷宗。
6. 在卷宗中切换“源码定位 / 控制流路径 / 验证日志”；验证日志只显示异常摘要，不显示测试输入。
7. 在报告页查看“大模型服务代码安全审计”章节，或导出 JSON、HTML、PDF。

## 防御性测试

```powershell
python -m pytest tests/source_audit tests/dynamic_validation tests/report -q
npm run lint
npm run build
```

动态框架单元测试使用 Fake Probe、Fake Monitor 和 Fake Sandbox，不发送真实网络请求。接入实际沙箱时，应把本地服务和验证器放入同一隔离网络命名空间，并使用快照/临时容器完成重置。

## 结果如何判断

- `candidate`：静态规则命中，尚未独立复核。
- `confirmed/rejected/uncertain`：只能由 Verification 层写入。
- `MODEL_REASONING_SUMMARY`：智能体的上下文研判，只是辅助证据。
- `RUNTIME_TRACE`：受控健壮性观察；仅有合格沙箱证明时生成。
- 未运行动态验证时，报告必须显示“未执行”，不能显示“安全”或“已验证”。

## 当前实现边界

Tree-sitter AST/CFG 和污点规则已实装于 Go/C/C++；规则库、智能体研判、证据链、卷宗和报告已接通。动态模块已实现可注入的核心框架与 fail-closed 策略，实际服务隔离依赖课程实验机提供符合 `ResettableSandbox` 协议的 Adapter；未配置时不会在 API 宿主机直接执行目标。
