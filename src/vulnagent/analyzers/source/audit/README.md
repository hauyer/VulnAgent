# Source Audit（成员 3）

输入 `SourceAnalysisResult`，输出统一 `VulnerabilityCandidate`。只允许依赖 Contracts、LLM 接口和 Adapter 接口；禁止确认漏洞或导入具体 Verification Agent。

## Python 规则审计基线

`PythonSourceAuditor` 是 V0.3 首条真实源码审计能力。它仅重新读取成员 2 已写入 `SourceAnalysisResult.files` 的 Python 文件，进行安全规则所需的 AST 检查；不会重新扫描项目、处理未列出的文件、解析其他语言或执行目标代码。

当前规则覆盖：

| 规则 | CWE | 主要信号 |
| --- | --- | --- |
| `VA-PY-CMD-001` | CWE-78 | 受污染或动态命令进入 `os.system`、`os.popen`、危险 `subprocess` 调用 |
| `VA-PY-SQL-001` | CWE-89 | 受污染查询进入 `execute` 或 `executemany` |
| `VA-PY-PATH-001` | CWE-22 | 受污染路径进入文件访问 API |
| `VA-PY-DESER-001` | CWE-502 | 受污染或动态数据进入不安全反序列化 API |
| `VA-PY-EVAL-001` | CWE-95 | 受污染或动态表达式进入 `eval` 或 `exec` |

审计器识别 `input`、`sys.argv`、环境变量、常见 Web request 数据和路由参数，并在函数内跟踪赋值、字符串拼接、格式化及简单分支。参数化 SQL、`yaml.safe_load`、未启用 shell 的 subprocess 参数列表，以及经 `basename`/`secure_filename` 处理的路径不会被上述规则直接报告。

每个结果始终保持 `CANDIDATE`，并在 metadata 中记录规则编号、sink、source、轻量 taint path、代码片段与已知限制。最终确认或拒绝仍由 Verification 边界负责。

## 使用与测试

```python
from vulnagent.analyzers.source.audit import PythonSourceAuditor

findings = await PythonSourceAuditor().audit(source_analysis_result)
```

```text
pytest tests/source_audit
pytest tests/contracts tests/architecture
```

## 已知限制

- 当前只分析 Python，污点传播限于单个函数，不能替代工业级跨过程污点分析。
- 动态派发、反射、复杂容器别名和自定义净化器可能无法准确识别。
- `mock` Profile 继续注入 Mock 能力；`v03-source` Profile 通过 `CapabilityBundle` 注入真实 Parser/Auditor。
- `SourceAuditAgent` 根据能力输出区分 Mock 与真实结果，并把 location、snippet、taint path 和 rule metadata 转换为统一 Evidence。
