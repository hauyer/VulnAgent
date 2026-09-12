# Report（成员 9）

只消费 Task、VulnerabilityCandidate、VerificationResult 和 Evidence，输出 `ReportResult`。禁止读取 Analyzer、Fuzzer 或 Agent 内部对象，也禁止 import `vulnagent.verification`（依赖边界，见 `tests/architecture/test_dependency_rules.py`）。

报告包含任务概览、状态汇总、每个 Finding 的 Verification 和关联 Evidence、轻量 Evidence Graph，以及缺失证据和未复核 Finding 的限制说明。报告由结构化数据生成，不能将模型文本当作确认依据。

## 输出区块

`ReportResult.content` 在既有键之外，确定性地产出以下区块（键名英文，新增人类可读文案为中文）：

- `summary.findings_by_severity` / `summary.severity_ordered_finding_ids`：按严重度（CRITICAL→INFO，缺失/未知归 `UNKNOWN`）零填充统计与全量排序；`findings[]` 数组本身保持输入顺序不变。
- `findings[].severity`：该 Finding 的原始值、规范化 label、rank、中文名。
- `findings[].reasoning`：复核结论——是否经过验证、有效状态（Verification 优先于 Finding）、置信度、`rationale` 逐字引用、依据 Evidence、状态对应的中文说明。
- `findings[].remediation`：修复建议——优先级（P0·紧急…P4·信息，`rejected` 为“无需处理”）、中文动作要点、知识来源（`CWE-<n>` / `type:<vt>` / `generic` / `rejected`）与免责声明。
- `cwe_classification`：按规范化 CWE 分组的清册（含计数、最高严重度、组内 Finding 列表）；无 CWE 归入 `未关联CWE` 桶且恒在最后。属于清册视图，包含 `rejected`。
- `evidence_timeline`：全部 Evidence 按 `created_at` 升序（同刻按 `evidence_id`）的时间线，标注其关联的 Finding/Verification，便于回放证据链如何形成。
- `risk_summary`：风险摘要——最高风险等级、确定性中文标题句、计数与 `top_risks`。风险视图排除 `rejected`（在 `counts` 与标题句中以“已排除”计数）；`candidate/verifying/uncertain` 视为待复核，计入风险但优先级下移。
- `software_code_security`：大模型服务代码安全章节；按统一 Finding 统计风险类型/等级，并为每条代码风险生成源码定位、CFG、污点路径、静态证据、动态摘要、智能体研判、独立复核和修复建议组成的卷宗。
- `compliance_notice`：固定标注“仅用于安全审计与防御研究，仅限教学实验使用”。

修复建议由 Report 内部小型 CWE/类型中文知识表与泛化兜底生成，仅作需人工复核的通用指引，绝不把文本当作权威确认（每项附 `disclaimer`）。本模块不修改任何公共 Contract。

测试入口：`pytest tests/contracts tests/evidence tests/report`（目录存在时）。

## 离线导出

`html.py` 与 `pdf.py` 只是 `ReportResult.content` 的展示投影，不读取 Analyzer/Fuzzer 内部对象，也不创建第二套 Finding 或 Evidence Schema：

- HTML 为单文件离线页面，所有动态文本做 HTML 转义，并设置禁止脚本和外部资源的 CSP；
- PDF 使用可选 `report-export` 依赖，以中文 CID 字体生成可打印分页报告；
- 两者均包含任务/风险摘要、Finding、Verification、修复建议、关联 Evidence、Evidence 时间线和完整性限制；
- 写入采用同目录临时文件替换，失败时不留下半份正式产物。

```powershell
python -m pip install -e ".[report-export]"
python scripts\export_report_html.py --input artifacts\demos\v04\source.json --output artifacts\demos\v04\source.html
python scripts\export_report_pdf.py --input artifacts\demos\v04\source.json --output artifacts\demos\v04\source.pdf
```
