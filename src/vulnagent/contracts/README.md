# PUBLIC CONTRACT

本目录是跨模块唯一公共协议层，只存放 DTO、Enum、Protocol、结构化事件和统一错误，不得包含业务算法、数据库实现、文件 IO、Agent 推理或外部工具调用。

冻结模型包括 Task、TaskStatus、AgentMessage、SourceAnalysisResult、BinaryAnalysisResult、VulnerabilityCandidate、Evidence、VerificationResult、FuzzRequest、FuzzResult 和 ReportResult。变更须由成员 1 协调，并同步文档、兼容层与 `tests/contracts/`。

## V0.5 新增契约（Evidence Provenance / Tool Adapter）

- `EvidenceV2`（`evidence_v2.py`）：带溯源字段（`analysis_run_id` / `derivation_id` / `independence_group` / `producer` / `parent_evidence_ids`）的证据 DTO；`to_legacy()` 将溯源信息压入 `Evidence.data["provenance"]`，旧存储与验证边界无需改动；`from_evidence()` 可从存量证据重建。
- `tool.py`：外部工具统一边界，含 `ToolHealth`、`ToolExecutionRequest`、`ToolExecutionResult`（缺省 `success=False`，失败不炸任务）、`NormalizedToolFinding`、`ProgramFact`、`ArtifactRef` 与 `ToolAdapter` Protocol。任何 Semgrep / Joern / Ghidra / AFL / angr 接入都必须实现该边界。
- 验证语义升级（`verification/independence.py` + `EvidenceVerifier` 0.4.0）：静态佐证按**独立来源（independence_group）**计数；同一分析器拆出的多个 EvidenceType 只算 1 个独立来源；无溯源字段的存量证据回退为按类型计数，行为与旧版完全一致。
- `candidate.py`（Candidate Fusion）：`CandidateFingerprint`（CWE + 归一化位置 + sink + function + taint source）与 `FusedCandidate`（多引擎合并结果）；融合引擎在 `analyzers/source/fusion/`。
