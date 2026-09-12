# Source Audit（成员 3）

输入 `SourceAnalysisResult`，输出统一 `VulnerabilityCandidate`。只允许依赖 Contracts、LLM 接口和 Adapter 接口；禁止确认漏洞或导入具体 Verification Agent。

## 多语言规则审计基线

`MultiLanguageSourceAuditor` 组合 `PythonSourceAuditor` 与 `NativeSourceAuditor`。前者仅重新读取成员 2 已写入 `SourceAnalysisResult.files` 的 Python 文件；后者只消费 Parser 写入 `metadata.native_analysis` 的 C/C++/Go 归一化事实。两者都不会执行目标代码。

当前规则覆盖：

| 规则 | CWE | 主要信号 |
| --- | --- | --- |
| `VA-PY-CMD-001` | CWE-78 | 受污染或动态命令进入 `os.system`、`os.popen`、危险 `subprocess` 调用 |
| `VA-PY-SQL-001` | CWE-89 | 受污染查询进入 `execute` 或 `executemany` |
| `VA-PY-PATH-001` | CWE-22 | 受污染路径进入文件访问 API |
| `VA-PY-DESER-001` | CWE-502 | 受污染或动态数据进入不安全反序列化 API |
| `VA-PY-EVAL-001` | CWE-95 | 受污染或动态表达式进入 `eval` 或 `exec` |
| `VA-NATIVE-MEM-001` | CWE-120 | `strcpy/sprintf/gets` 等无界写入；`memcpy/memmove/strncpy/strncat` 的固定长度越界或长度受污染且缺少边界检查 |
| `VA-NATIVE-INT-001` | CWE-190 | 受污染的算术表达式进入内存分配大小或数组/切片下标计算，且缺少范围检查 |
| `VA-NATIVE-BOUNDS-001` | CWE-129 | 受污染数组/切片下标缺少前置范围检查 |
| `VA-NATIVE-INPUT-001` | CWE-20 | API 参数或网络/输入函数数据进入敏感长度、下标、拷贝操作前，未观察到类型/长度/范围检查 |

审计器识别 `input`、`sys.argv`、环境变量、常见 Web request 数据和路由参数，并在函数内跟踪赋值、字符串拼接、格式化及简单分支。参数化 SQL、`yaml.safe_load`、未启用 shell 的 subprocess 参数列表，以及经 `basename`/`secure_filename` 处理的路径不会被上述规则直接报告。

每个结果始终保持 `CANDIDATE`，并在 metadata 中记录规则编号、sink、source、轻量 taint path、代码片段与已知限制。最终确认或拒绝仍由 Verification 边界负责。

C/C++/Go 分析把函数参数视为 API 边界输入，同时识别 `recv/read/fgets/scanf` 等缓冲区输入和常见 Go 请求/解码调用；污染通过局部赋值传播到危险拷贝、内存分配大小及数组/切片下标。条件中出现与变量相关的比较、`len` 或 `sizeof` 会作为启发式边界检查信号。所有结论都是待复核候选，而不是“已确认漏洞”。

## 使用与测试

```python
from vulnagent.analyzers.source.audit import MultiLanguageSourceAuditor

findings = await MultiLanguageSourceAuditor().audit(source_analysis_result)
```

```text
pytest tests/source_audit
pytest tests/contracts tests/architecture
```

## 已知限制

- 污点传播限于单个函数，不能替代工业级跨过程、路径敏感和上下文敏感分析。
- 宏、指针别名、模板、动态派发、反射、复杂容器别名和自定义净化器可能无法准确识别。
- “观察到检查”采用保守启发式匹配；候选仍需 Verification 独立复核并结合证据链过滤误报。
- `mock` Profile 继续注入 Mock 能力；`v03-source` Profile 通过 `CapabilityBundle` 注入真实 Parser/Auditor。
- `SourceAuditAgent` 根据能力输出区分 Mock 与真实结果，并把 location、snippet、taint path 和 rule metadata 转换为统一 Evidence。
