# Microtar 线索审查卡（S5 / 工作包 C 第 5 步）

> 日期：2026-09-26　对象：`p1c-microtar-exploration`（候选 `vuln-mt-0001`）
> 审查结论摘要：**根因真实、属已公开漏洞族（独立重复发现，非新漏洞）；溯源为种子驱动回放而非盲态自动生成；正式主链已补全（Verification → CONFIRMED，仅 observed_fault 层）。**

## 1. 种子溯源：7 个种子是否含预设触发样本

| 种子 | 大小 | 生成时间 | 内容 | 判定 |
|---|---|---|---|---|
| seed_empty.tar | 10240 | 2026-09-26 09:51 | 空 tar（5 个 PAX 归档之一） | 常规语料 |
| seed_single.tar | 10240 | 同上 | 单条目 | 常规语料 |
| seed_multi.tar | 10240 | 同上 | 多条目 | 常规语料 |
| seed_longname.tar | 10240 | 同上 | 长文件名 | 常规语料 |
| seed_binary.tar | 10240 | 同上 | 二进制文件条目 | 常规语料 |
| **seed_nonnull_name_validchk.tar** | 512 | 2026-09-26 09:51 | name 字段 100×'A' 无 NUL；checksum 字段 `100075  ` 全非 NUL、校验和有效；typeflag='0' | **预设触发样本** |
| **seed_strcpy_write_chk_nul.tar** | 512 | 2026-09-26 09:52 | name 字段 100×'A' 无 NUL；checksum `100075 \x00`（末字节 NUL） | **预设触发样本** |

**结论**：7 个种子中 5 个为常规语料、2 个为**手工构造的触发样本**（文件名
本身即描述缺陷行为：non-NUL name + valid checksum / strcpy + checksum NUL）。
字节核验（name 全 'A' 无 NUL、checksum 全非 NUL 或末字节 NUL）与生成时间
（同一分钟内批量写入）一致。**候选并非由盲态 fuzz 变异自动生成**，而是
预先放置的触发种子在 libFuzzer 单输入回放模式下复现。

## 2. ASan 原始日志与最小输入复核

- 原始日志保存完好：`third_party/microtar/src/crash_report_1.txt`（4540 B）、
  `crash_report_2.txt`（4543 B）、`crash_report_strcpy.txt`（4244 B）。
- `crash_report_1.txt` 关键行：`ERROR: AddressSanitizer: stack-buffer-overflow
  READ of size 366`，栈：`_asan_wrap_strnlen → __stdio_common_vsscanf → sscanf
  → mtar_read_header → LLVMFuzzerTestOneInput`；运行方式为
  `Running 1 inputs 1 time(s) each. Running: ..\fuzz\seeds\seed_nonnull_name_validchk.tar`
  ——**明确是种子回放，不是变异输入**。
- 最小输入即两个 512 字节手工头部（不依赖文件系统，内存流驱动）。
- 回放次数记录：ev-mt-001 记录 2 次、ev-mt-002 记录 1 次（均 exit=1）。

## 3. 公告/CVE 判重：是否同根因、同版本

外部检索（2026-09-26，NVD/CVE.org/Red Hat Bugzilla/VulnCheck/Snyk）：

| CVE | 描述 | 与本次根因一致性 | 版本 |
|---|---|---|---|
| CVE-2026-43623 | raw_to_header() strcpy 非 NUL 字段 → 栈溢出（写入 ≤355 B） | 同根因（strcpy 路径） | 0.1.0 |
| CVE-2026-55738 | 同上，strcpy 越界读（Red Hat 2489845） | 同根因（strcpy 路径） | 0.1.0 |
| CVE-2026-54417 | mtar_next() 32 位整数溢出 → 无限循环 DoS | 兄弟缺陷（非本次复现路径） | 0.1.0 |
| CVE-2026-71267 | 写路径 mtar_write_file_header strcpy(h.name,name) | 兄弟缺陷（写路径） | 0.1.0 |

**结论**：本次复现的 sscanf 校验和越界读（366 B）与 strcpy 越界读（357 B）
属于 raw_to_header 非 NUL 固定宽度字段缺陷族，与 CVE-2026-43623/55738
**同根因、同版本（0.1.0）**。判重定性：`known_duplicate`（独立重复发现）。
不申报新漏洞，披露流程 N/A。

## 4. 盲态自动生成性验证

- 证据 `ev-mt-001/002` 的 `created_by="BlindDiscoveryRunner(p1c)"`、
  `source_type="dynamic_fuzz"` 与既有描述 "independently re-discovered blind"
  **与事实不符**：触发输入是预置手工种子，非 fuzz 变异产出。
- 修正后的诚实表述：**种子驱动复现（seed-driven reproduction）**。触发
  输入为构造性语料，缺陷本身真实、可重复，但发现路径不是盲态自动发现。

## 5. 同输入安全版 / 修复建议

- 上游 rxi/microtar 自 2017 年附近不再维护（固定修订 `27076e1`），**无修复
  版可 diff**；不存在"同输入安全版"。
- 社区修复建议（Orbis AppSec 2026-07）与安全常识一致：raw_to_header /
  header_to_raw 中所有 `sscanf`/`strcpy`/`sprintf` 改为有界复制
  （`memcpy` + 显式 NUL 终止、`snprintf`），长度上限按 ustar 字段宽
  （name/linkname=100、prefix=155）。
- 本项目 v0.2 边界内**不自动生成 patch**（与路线图 L4 暂缓一致），仅记录
  修复方向。

## 6. 正式主链（Candidate / Evidence / Verification）状态

| 环节 | 状态 |
|---|---|
| Candidate | `candidates.jsonl` 冻结（vuln-mt-0001，status=verifying，severity=medium，CWE-121） |
| Evidence | `evidence.jsonl` 冻结（ev-mt-001..004：2×CRASH_LOG、1×TOOL_RESULT、1×SOURCE_LOCATION） |
| Verification | **本轮补全**：`verification.jsonl`（layered-v1）→ **CONFIRMED**，conf=0.95，layers=`observed_fault=True, root_cause_supported=False, security_impact_supported=False`。含义：可复现运行故障成立；根因归因未达双独立静态证据门槛；影响层不单独确认。 |
| 披露 | `not_submitted`（重复发现；披露路由 N/A） |

**结论（总）**：microtar 线索为**已公开漏洞族的独立重复发现**，根因与版本
经外部记录核实一致；溯源定性修正为种子驱动复现；主链证据完整、Verification
已如实落库。不构成"未公开漏洞"，课件④保持未提交。
