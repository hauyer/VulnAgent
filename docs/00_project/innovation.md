# VulnAgent 创新设计

## 1. 创新目标

本项目的创新不以“使用了大语言模型”为核心。

单纯调用 LLM 对代码进行漏洞判断不能构成足够的软件系统创新。

VulnAgent 重点研究：

**如何将大语言模型作为安全分析系统中的推理节点，并与传统程序分析、动态测试以及多智能体协同机制结合。**

## 2. 创新点一：面向漏洞挖掘的多智能体协作架构

传统 LLM 漏洞分析通常采用：

```text
代码
→ Prompt
→ LLM
→ 漏洞结果
```

VulnAgent 将漏洞分析拆分为多个具有明确职责的 Agent：

- PlannerAgent
- SourceAuditAgent
- BinaryAnalysisAgent
- FuzzAgent
- VerificationAgent
- ReviewerAgent
- ReportAgent

不同 Agent 不只是执行不同 Prompt，而具有：

- 独立职责
- 独立输入输出
- 明确状态
- 结构化消息
- 分析工具
- 中间结果
- 可独立测试的能力

PlannerAgent 根据目标信息和中间分析结果动态决定后续任务。

因此形成：

```text
Task Planning
→ Analysis
→ Feedback
→ Verification
```

的协同过程。

## 3. 创新点二：静态分析与动态 Fuzz 闭环

传统静态扫描与 Fuzz 通常相互独立。

VulnAgent 尝试建立：

```text
Static Analysis
→ Attack Surface
→ Fuzz Target
→ Seed Generation
→ Runtime Execution
→ Crash / Coverage
→ Feedback
→ Further Analysis
```

静态分析负责缩小搜索空间，动态测试负责验证程序真实行为。

未来可以进一步研究 Agent 根据：

- 参数类型
- 协议格式
- 分支条件
- 危险 API
- 数据流信息

生成更具有语义的 Fuzz Seed。

## 4. 创新点三：独立漏洞复核机制

LLM 容易产生幻觉。

静态规则也可能产生误报。

因此 VulnAgent 将 Discovery 与 Verification 拆开。

统一流程：

```text
Candidate
→ Evidence Collection
→ Independent Verification
→ Confirmed / Rejected / Uncertain
```

VerificationAgent 不直接继承发现 Agent 的自然语言判断，而主要根据结构化漏洞信息和证据重新进行分析。

该机制可以用于研究：

**是否能够显著降低漏洞误报率。**

## 5. 创新点四：统一漏洞证据链

针对“LLM 给出结论但缺乏证明”的问题，系统为漏洞建立统一 Evidence 对象。

证据可包括：

- Source Location
- Code Snippet
- Call Path
- Data Flow
- Taint Path
- Binary Address
- Disassembly
- CFG Path
- Fuzz Input
- Coverage
- Crash
- Stack Trace
- Runtime Trace
- Sanitizer
- Verification Result

不同证据通过 `evidence_id` 与 `VulnerabilityCandidate` 关联。

最终漏洞报告不只给出：

“存在缓冲区溢出”

而能够描述：

```text
Source
→ Path
→ Runtime
→ Verification
```

形成完整的漏洞证据链。

## 6. 创新点五：统一源代码与二进制漏洞表示

不同分析方式通常输出不同格式。

VulnAgent 规定：

```text
Source Analysis
Binary Analysis
Fuzz
LLM Analysis
```

全部输出统一：

`VulnerabilityCandidate`

因此能够共享：

- Verification
- Deduplication
- Severity
- Evidence
- Report
- Experiment

实现异构分析结果的统一组织。

## 7. 创新点六：Agent-Guided Fuzzing

传统 Fuzz 很大程度依赖随机或覆盖率反馈。

VulnAgent 已实现由结构化 Source/Binary Candidate 派生的风险引导信息，用于：

- 攻击面选择
- 目标函数选择
- Seed 生成
- Mutation Strategy
- Crash 分析
- 优先级调整

当前固定预算实验可以比较：

**Traditional Fuzz**

与：

**Agent-Guided Fuzz**

在以下指标上的差异：

- 覆盖率
- Crash 数量
- 漏洞发现速度
- 有效输入比例

引导字典仅使用项目标记和解析器边界字符，不自动生成命令、SQL 或 Exploit。Fuzz Evidence 会同时记录来源 Finding ID、风险类型和具体变异策略，使 Static→Dynamic 关系可追踪。

## 8. 创新点七：异构 LLM 可替换与横向比较

VulnAgent 不绑定单一模型。

所有模型通过统一 LLM Adapter 使用。当前已实现 DeepSeek、智谱 GLM 与 Kimi K2.6 的非流式 Chat Completions Adapter，并由配置注入 Planner；无 Key 时使用 Mock 或明确失败。统一 `generate_with_usage` 在保持 `generate -> str` 兼容的同时记录供应商返回 Token、缓存命中、延迟和版本化费率估算。

因此可以研究：

```text
DeepSeek
vs
GLM
vs
Kimi
```

在以下方面的差异：

- 漏洞识别能力
- 假阳性
- 推理稳定性
- Token 成本
- 响应时间
- 不同代码长度表现

2026-09-11 已在同一 20 样本 manifest 上完成三家模型各 20 次真实调用，并与 Evidence-First Full 同批比较。三家分类 F1 均为 1.0，但 LLM-only Evidence Coverage 为 0、Full 为 1.0；因此该创新的可验证价值是“异构替换、成本/延迟可测、证据闭环可对照”，不是宣称在小型教学集上拥有虚假的精度领先。

## 9. 创新验证原则

所有创新点最终必须通过实验进行支撑。

不能只写：

“本系统使用多智能体，因此效果更好。”

应设计对应消融实验。

例如：

```text
Multi-Agent vs Single-Agent
Verification vs No Verification
Agent Guided Fuzz vs Traditional Fuzz
Evidence Fusion vs LLM Only
```

从而形成：

```text
Architecture
→ Hypothesis
→ Experiment
→ Result
→ Conclusion
```

的完整研究闭环。
