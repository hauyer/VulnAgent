# Evidence Schema

## 1. 设计目标

Evidence 用于保存能够支持或否定漏洞结论的信息。

VulnAgent 强调：

**Evidence First**

漏洞报告必须尽可能给出可复核证据。

## 2. EvidenceType

```python
class EvidenceType(str, Enum):

    SOURCE_LOCATION = "source_location"
    CODE_SNIPPET = "code_snippet"

    CALL_PATH = "call_path"
    DATA_FLOW = "data_flow"
    TAINT_PATH = "taint_path"

    BINARY_ADDRESS = "binary_address"
    DISASSEMBLY = "disassembly"
    CFG_PATH = "cfg_path"

    FUZZ_INPUT = "fuzz_input"
    COVERAGE = "coverage"

    CRASH_LOG = "crash_log"
    STACK_TRACE = "stack_trace"
    SANITIZER_OUTPUT = "sanitizer_output"
    RUNTIME_TRACE = "runtime_trace"

    TOOL_RESULT = "tool_result"

    MODEL_REASONING_SUMMARY = "model_reasoning_summary"

    VERIFICATION_RESULT = "verification_result"
```

## 3. Evidence

```python
class Evidence(BaseModel):

    evidence_id: str

    task_id: str

    evidence_type: EvidenceType

    source: str

    description: str

    artifact_path: str | None = None

    data: dict[str, Any] = Field(default_factory=dict)

    reliability: float

    created_by: str

    created_at: datetime
```

## 4. Reliability

Evidence 可以包含：

`reliability`

范围：

`0.0 ～ 1.0`

此字段表示证据来源可靠程度，不是漏洞概率。

例如：

- 真实 Crash：0.95
- LLM 推理：0.50
- 静态规则：视规则准确性调整

## 5. Evidence 与 Vulnerability

通过：

`evidence_ids`

建立关系。

一个 Evidence 可以被多个 Vulnerability 引用。

## 6. Artifact

大型内容不要直接进入数据库 JSON。

例如：

- Crash Dump
- Binary
- Long Log
- Fuzz Corpus
- 截图

保存于：

`artifacts/`

Evidence 中记录：

`artifact_path`

## 7. LLM Evidence

LLM 输出只能作为：

`MODEL_REASONING_SUMMARY`

不允许将：

“模型认为这里存在漏洞”

作为唯一 Confirm Evidence。

## 8. Confirmation 建议

一个漏洞确认最好满足至少一个强证据：

- 可复现 Crash
- Sanitizer
- 明确数据流
- 明确危险调用路径
- 动态 Trace
- 受控验证结果

或者多个中等证据一致指向同一漏洞。

## 9. 示例

```json
{
  "evidence_id": "evidence-001",
  "task_id": "task-001",
  "evidence_type": "code_snippet",
  "source": "source_analyzer",
  "description": "Unsafe strcpy call with externally controlled source.",
  "artifact_path": null,
  "data": {
    "file": "src/parser.c",
    "line": 46,
    "function": "parse_packet"
  },
  "reliability": 0.8,
  "created_by": "source_audit",
  "created_at": "2026-09-07T12:00:00+08:00"
}
```

## 10. Evidence Chain

最终报告应能够展示类似：

```text
External Input
      ↓
parse_packet()
      ↓
user_buffer
      ↓
strcpy()
      ↓
stack buffer
      ↓
ASan crash
      ↓
Verification confirmed
```

这是 VulnAgent 最重要的可解释性输出之一。
