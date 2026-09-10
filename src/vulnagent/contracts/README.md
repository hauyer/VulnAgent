# PUBLIC CONTRACT

本目录是跨模块唯一公共协议层，只存放 DTO、Enum、Protocol、结构化事件和统一错误，不得包含业务算法、数据库实现、文件 IO、Agent 推理或外部工具调用。

冻结模型包括 Task、TaskStatus、AgentMessage、SourceAnalysisResult、BinaryAnalysisResult、VulnerabilityCandidate、Evidence、VerificationResult、FuzzRequest、FuzzResult 和 ReportResult。变更须由成员 1 协调，并同步文档、兼容层与 `tests/contracts/`。
