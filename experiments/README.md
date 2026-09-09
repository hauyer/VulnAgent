# Experiments（成员 9）

保存实验配置、指标与消融方案。实验必须记录版本、输入、配置和输出位置；不得把生成的大体积产物提交到公共协议目录。

`run_metrics.py` 从人工标注的 JSON 行生成可复现的 JSON/CSV 指标。每行包含 `method`、`expected`（`vulnerable` 或 `clean`）和 `observed`，并可附加 `duration_seconds`、`evidence_complete`。建议比较 `static_baseline`、`llm_only`、`multi_agent_no_verification` 和 `vulnagent_full`，但不预设任何结果。

```text
python experiments/run_metrics.py labelled-results.json --output-dir results/run-001
```
