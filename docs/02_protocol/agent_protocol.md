# VulnAgent Agent Protocol

## 1. 目的

为了避免不同开发人员通过任意 dict 和自然语言传递数据，VulnAgent 定义统一 Agent 通信协议。

Agent 之间的所有正式消息使用：

`AgentMessage`

## 2. AgentMessage

建议 Schema：

```python
class AgentMessage(BaseModel):

    message_id: str
    task_id: str

    sender: str
    receiver: str | None

    message_type: AgentMessageType

    payload: dict[str, Any]

    evidence_ids: list[str]

    created_at: datetime
```

## 3. Message Type

建议：

- TASK
- PLAN
- REQUEST_ANALYSIS
- ANALYSIS_RESULT
- VULNERABILITY_CANDIDATE
- REQUEST_VERIFICATION
- VERIFICATION_RESULT
- FUZZ_REQUEST
- FUZZ_RESULT
- EVIDENCE_UPDATE
- REVIEW_REQUEST
- REVIEW_RESULT
- REPORT_REQUEST
- REPORT_RESULT
- ERROR

## 4. AgentResult

Agent 执行结束必须返回：

```python
class AgentResult(BaseModel):

    agent_name: str

    success: bool

    messages: list[AgentMessage]

    findings: list[VulnerabilityCandidate]

    evidence: list[Evidence]

    artifacts: list[str]

    error: str | None = None
```

## 5. Agent 基类

```python
class BaseAgent(ABC):

    name: str

    @abstractmethod
    async def run(
        self,
        task: Task,
        context: AnalysisContext,
    ) -> AgentResult:
        ...
```

## 6. PlannerAgent

输入：

- Task
- Target
- 已有 Context

输出：

`PLAN`

示例 payload：

```json
{
  "steps": [
    {
      "agent": "source_audit",
      "priority": 1,
      "reason": "C source project detected"
    },
    {
      "agent": "fuzz",
      "priority": 2,
      "reason": "Input parsing surface exists"
    }
  ]
}
```

## 7. SourceAuditAgent

输入：

`REQUEST_ANALYSIS`

输出：

`ANALYSIS_RESULT`

以及：

`VULNERABILITY_CANDIDATE`

禁止直接输出：

`CONFIRMED`

## 8. FuzzAgent

输入：

`FUZZ_REQUEST`

payload 可包括：

- target
- target_function
- seed_hints
- time_budget
- resource_limit

输出：

`FUZZ_RESULT`

并附带 Evidence。

## 9. VerificationAgent

输入：

`REQUEST_VERIFICATION`

包含：

- candidate_id
- evidence_ids

输出：

`VERIFICATION_RESULT`

## 10. ReviewerAgent

用于：

- 结果冲突
- 高危漏洞
- Confidence 较低
- Verification 无法判断

ReviewerAgent 不默认参与每一个漏洞。

## 11. 错误处理

Agent 不应通过抛出未处理异常结束整个系统。

可恢复错误应转为：

`AgentResult.success = False`

并提供：

`error`

严重系统错误由 Orchestrator 决定是否终止任务。

## 12. 幂等性

同一 `task_id` 下重复执行 Agent 时：

不得产生无法控制的重复数据。

Finding 与 Evidence 应拥有稳定唯一 ID。

## 13. 可追踪性

AgentMessage 必须保留：

- task_id
- message_id
- sender
- created_at

方便最终重建 Agent 工作流。
