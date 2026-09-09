# Evidence（成员 9）

收集、关联、存储和查询统一 `Evidence`。对外只暴露 `EvidenceRepository`，不理解具体安全工具或 LLM 厂商内部对象。

`InMemoryEvidenceStore` 会对同一任务中来源、类型、描述、工件与数据完全相同的证据去重。需要建立 Finding 关联时，生产方在 `Evidence.data` 中使用 `finding_id` 或 `finding_ids`；这保持冻结的公共 Contract 不变。`build_evidence_graph` 仅从 Finding、Evidence 和 VerificationResult 生成可展示的节点与边。

测试入口：`pytest tests/contracts tests/evidence tests/report`（目录存在时）。
