# VulnAgent V0.5 加壳与混淆还原技术升级方案

## 1. 建设目标与合规边界

本升级面向北京邮电大学网络空间安全课程设计中的防御性二进制安全审计实验。分析对象必须是自行开发、明确授权的本地教学样本；动态 PE 还原只能在隔离的 Windows 调试执行器中运行，DEX 动态还原只能连接显式指定的 `emulator-*` 本地模拟器。系统不提供许可证绕过、反调试对抗、真实设备注入或通用利用代码。

升级不是把“检测到壳”直接当作“已经还原”，而是区分四个可审计状态：

1. `identified`：由文件结构事实推断保护类型；
2. `analysis_only`：给出策略，但没有生成新文件；
3. `restored`：生成派生文件且通过结构解析；
4. `validated`：恢复结果能够进入反汇编/伪代码分析，并形成后续 Evidence。

这样可以避免答辩时把方案设计、外部工具建议或用户填写的标签冒充实测结果。

## 2. 本轮代码落地范围

| 能力 | 当前实现 | 运行边界 |
|---|---|---|
| 8 类 PE 保护识别 | 已实现多信号分类、强度分级、解释证据与策略选择 | 静态、默认启用 |
| UPX 静态还原 | 复用既有 UPX Adapter，输出副本后重新解析 | 需安装 UPX，需授权 |
| ASPack/FSG/PECompact/Upack/NSIS/轻量 VM | 已实现识别和动态恢复策略编排 | 真正动态转储需注入隔离调试 Provider |
| 导入表修复 | 已实现独立 `ImportTableRebuilder`，由 API 解析轨迹生成 Descriptor/ILT/IAT/Hint-Name | 输入为隔离执行器返回的快照 DTO |
| PE 结构重建 | 已实现 PE32/PE32+ Header、Section Table、Data Directory、入口点和导入节重建 | 不在 API 进程执行样本 |
| DEX/APK 静态分析 | 已实现 DEX Header、校验和、签名、表规模、APK 多 DEX 清单和保护标志解析 | 静态、默认启用 |
| Frida DEX 转储 | 已定义本地模拟器 Provider 契约、授权和结果校验/落盘流程 | Provider 默认未配置，禁止真实设备 |
| 四类 OLLVM 还原 | 已实现 CFG 平坦化识别、虚假流过滤、等价指令重写、字符串解码及前后对比 | 静态、默认启用 |
| LLM 语义增强 | 已实现 `BaseLLM` 注入边界和 JSON 注释协议 | 模型只做辅助标注，不修改字节、不确认漏洞 |
| 两个专属 Agent | 已接入 Runtime、Supervisor、Lifecycle、Evidence 与 Tool Registry | 有界路由，失败自动回退 |
| UI 与报告 | 已加入强度选择、恢复指标、前后对比、拓扑节点、JSON/Markdown/HTML/PDF 专项章节 | 消费后端 Evidence，不在前端重新判定 |

特别说明：本仓库交付的是安全可测试的“动态恢复核心 + Provider 接口”。Windows Debug API 与 Frida 的实际附加/启动操作必须部署在课程实验机的隔离执行器中；未注入 Provider 时，系统返回 `not_configured`，不会伪造成功。

## 3. 总体架构

```text
Planner
  -> ProgramRestorationAgent
       -> 静态 PE/DEX/APK 解析
       -> ProtectionClassifier（8 类、多信号）
       -> 静态 UPX 或隔离 Snapshot Provider
       -> ImportTableRebuilder + PEImageRebuilder
       -> 可解析性校验
  -> BinaryAnalysisAgent（只使用通过校验的派生文件）
  -> CodeDeobfuscationAgent
       -> CFG/指令/字符串确定性还原
       -> 可选 LLM 语义注释
       -> 可读性评分
  -> FuzzAgent（仅显式动态授权）
  -> VerificationAgent（唯一有权给出最终漏洞状态）
  -> Reviewer -> ReportAgent
```

关键架构约束保持不变：Agent 不互相直接调用；Supervisor 是唯一编排入口；Capability 由 Composition Root 注入；程序恢复和混淆还原只产生 Evidence，不直接产生 `CONFIRMED` 漏洞。

## 4. PE 保护识别

### 4.1 保护矩阵

| 等级 | 家族 | 主要观测信号 | 首选策略 |
|---|---|---|---|
| L1 压缩 | UPX | `UPX0/UPX1`、UPX 文本、少导入、高熵 | UPX 静态副本还原，失败转快照 |
| L1 压缩 | ASPack | `.aspack/.adata`、ASPack 文本 | 静态 Adapter 或快照 |
| L1 压缩 | FSG | `FSG!/.fsg`、FSG 文本 | 静态 Adapter 或快照 |
| L2 加密 | PECompact | `PEC1/PEC2/.pec`、PECompact 文本 | OEP 快照、IAT 和 PE 重建 |
| L2 加密 | Upack | `UPACK/.upack`、Upack 文本 | OEP 快照、IAT 和 PE 重建 |
| L2 加密 | NSIS | `.ndata`、Nullsoft/NSIS 文本 | 解包 Adapter 或快照 |
| L3 轻量虚拟化 | VMProtect demo | `.vmp0/.vmp1/.vmp2`、VM 标记 | 路径跟踪、OEP 候选评分、快照、语义还原 |
| L3 轻量虚拟化 | Teaching VM | `.vcode/.vmdata/.vdispatch`、教学 VM 标记 | 解释器边界跟踪、热点路径和语义还原 |

### 4.2 多信号评分

分类器不读取用户声明来提高分数。节区标志命中计 55 分、文本标志命中计 30 分、导入稀疏计 8 分、高熵节计 5 分、入口点位于高熵节计 2 分；每个命中项都保存在 `protection_analysis.candidates[].evidence` 中。没有专属标志但出现“少导入 + 高熵 + 异常入口点”时只给出低置信度 `unknown_protector`，不武断归因。

## 5. 动态内存还原引擎

### 5.1 Provider 边界

`WindowsDebugSnapshotProvider.capture()` 是隔离执行器接口。实际 Provider 应完成以下步骤：

1. 校验任务授权、样本 SHA-256、时间/内存/进程配额；
2. 在断网 Windows VM 或受控 Job 中以 `DEBUG_ONLY_THIS_PROCESS` 启动教学样本；
3. 用 `WaitForDebugEvent` 处理创建进程、加载 DLL、异常和退出事件；
4. 在入口 Stub、写后执行内存转换、跨节跳转处建立 OEP 候选；
5. 通过线程上下文、节区归属、执行稳定性和导入解析完成度给候选打分；
6. 记录 `LoadLibrary`/`GetProcAddress`/`LdrGetProcedureAddress` 解析轨迹；
7. 用 `VirtualQueryEx + ReadProcessMemory` 复制已提交的映像内存；
8. 终止整个隔离 Job，返回 `MemorySnapshot`，不把进程句柄交给 Web 服务。

核心 DTO 包含 `image_base`、`entry_point`、位数、Machine、内存段权限/字节、API 解析轨迹和捕获证据。测试使用 `RecordedSnapshotProvider` 重放教师预先采集的快照，因此 CI 不执行未知程序。

### 5.2 导入表重建

`ImportTableRebuilder` 按 DLL 对 API 解析事件去重、排序，构造：

- 以全零项结尾的 `IMAGE_IMPORT_DESCRIPTOR` 数组；
- PE32 的 4 字节或 PE32+ 的 8 字节 ILT/IAT；
- DLL 名称和对齐后的 `IMAGE_IMPORT_BY_NAME`；
- 指向新 `.idata` 节 RVA 的 Import Data Directory。

ASLR 后的绝对 API 地址不会写回文件，只使用 DLL/符号身份重建可重定位导入，避免生成只在一次进程中有效的假 IAT。

### 5.3 PE 结构重建

`PEImageRebuilder` 根据内存段属性生成 `.text/.data/.r*` 等标准节，使用 0x1000 Section Alignment 和 0x200 File Alignment，重建 DOS Header、NT Header、Optional Header、Section Table、入口点、镜像大小和 `.idata`。写盘前后都受大小、段数、重叠和路径逃逸限制，最后使用项目自己的严格 PE Parser 重新解析。只有解析成功且确实生成派生文件时，`success` 才能为真。

### 5.4 自动回退

策略顺序是“可证明的低成本方案优先”：

```text
结构识别 -> 确定性静态 Adapter -> 隔离内存快照 -> IAT/PE 重建
         -> 严格解析 -> 反汇编/伪代码 -> 失败证据 + 原始静态分析回退
```

恢复 Agent 失败不会截断 BinaryAnalysisAgent。后者只会选择 `success=true` 且 `validation.parseable=true` 的派生文件，否则继续分析原文件。

## 6. DEX/APK 保护分析与还原

静态层支持 DEX 035、037–041，检查 Magic、File Size、Header Size、Adler32、SHA-1、字符串/类型/方法/类表规模和边界；APK 使用内存 ZIP 读取 `classes*.dex` 清单并限制条目数与解压大小。Bangcle、Ijiami、Legu、DexGuard 等标志只作为保护提示，不作为厂商归因的绝对证明。

动态层的 `FridaDexSnapshotProvider` 只接受 `emulator-*` 序列号。实验 Provider 可在 ART 的 DefineClass/OpenMemory 等版本适配点复制已经展开的 DEX，返回字节数组；主进程重新写入 File Size、SHA-1 Signature 与 Adler32，再验证 DEX Magic 和校验字段后保存为 `classes-restored-N.dex`。JADX/baksmali 可作为隔离执行器的后置 Validator；其成功输出应记录为工具证据，而不能仅以“文件存在”宣称可反编译。

ProGuard 的名称恢复优先使用课程样本构建时生成的 `mapping.txt`，因为这是精确、可复现的映射；无映射时 LLM 只能建议语义名称并标注为辅助推断，不能声称恢复了原始标识符。DexGuard 的控制流和字符串处理复用下述静态/动态证据链。

## 7. 四类混淆还原

### 7.1 控制流平坦化

从函数 CFG 统计入度、出度和回边，筛选“多前驱、多分支”的 Dispatcher 候选；结合状态变量比较/赋值位置形成 Case 转移关系。当前引擎输出 Dispatcher 候选、原始/恢复节点数和恢复 CFG，并明确说明结构候选不等同于原始源码顺序。

### 7.2 虚假控制流

从入口做有界可达性遍历，标记不可达节点；识别可代数证明的恒真奇偶谓词。若 `runtime_trace.executed_edges` 存在，则保留实际边并用静态边作保守回退，避免一次路径覆盖不足造成过度删除。

### 7.3 指令替换

只执行可以证明等价的规范化，例如 `x + (~y + 1) -> x - y`、双重按位非、异或零、加零。每个函数保存 `before`、`after` 和 `transformations`，不进行未经证明的猜测性字节改写。

### 7.4 字符串加密

支持可验证的 Hex/Base64 解码；XOR 仅在分析元数据已提取明确 Key 与密文时恢复。输出算法、密文、明文和 Key 来源，限制数量与长度。未知算法保留为待分析项，不以“乱码看起来像加密”为成功证据。

### 7.5 LLM 语义增强

确定性还原结果可交给 `SemanticRecoveryEnhancer`。模型只能返回 JSON 注释：业务逻辑摘要、建议函数名、关键审计位置和不确定性；它不能修改可执行文件、不能输出私有思维链、不能确认漏洞。可读性评分反馈由“控制流复杂度、goto/case 密度、已安全移除节点数”计算，报告展示 before/after 分数而非主观宣传。

## 8. Evidence 链与报告

专项证据源包括：

| 阶段 | Evidence source | 关键字段 |
|---|---|---|
| 保护识别/恢复 | `program_restoration` | 分类依据、策略、执行记录、产物、耗时、可解析性 |
| 结构/反编译 | `binary_reverse` | 函数、CFG、伪代码、工具记录 |
| 混淆还原 | `code_deobfuscation` | 四类命中、恢复 CFG、字符串、before/after、评分 |
| 语义注释 | `semantic_recovery` | 模型、公开注释、不确定性 |
| 漏洞结论 | `verification` | 使用的 Evidence ID、状态、置信度与依据 |

`StructuredReportGenerator` 从 Evidence 投影“二进制程序保护分析专项”，包含保护类型、强度、策略、恢复成功率字段、耗时、导入/函数可解析结果、混淆命中、可读性提升和证据链。React 页面、Markdown、离线 HTML 和 PDF 均消费同一结构化章节。

## 9. 前端升级

“漏洞测试实验室”新增：

- 保护强度：无保护、压缩保护、加密保护、轻量虚拟化、代码混淆；
- PE/ELF/DEX/APK 路径提示；
- 动态恢复授权和本地模拟器序列号；
- 恢复状态、耗时、结构可解析、可读性分数标签。

“二进制逆向工作台”新增保护归因、置信度、选定策略、PE 结构/IAT 修复指标、恢复前后伪代码对比和四类混淆标签。“Agent 拓扑”增加 Program Restoration Agent 与 Code Deobfuscation Agent，显示其模块路径和职责。“审计报告”增加独立绿色专项卡片与完整 Evidence Chain。

## 10. 关键代码索引

| 模块 | 文件 |
|---|---|
| 保护识别 | `src/vulnagent/analyzers/binary/protection.py` |
| DEX/APK 解析 | `src/vulnagent/analyzers/binary/reverse/_dex.py` |
| 动态 Provider 契约 | `src/vulnagent/analyzers/binary/restoration/dynamic.py` |
| 动态恢复编排 | `src/vulnagent/analyzers/binary/restoration/engine.py` |
| IAT 重建 | `src/vulnagent/analyzers/binary/restoration/imports.py` |
| PE 重建 | `src/vulnagent/analyzers/binary/restoration/pe_rebuild.py` |
| 静态混淆还原 | `src/vulnagent/analyzers/binary/deobfuscation/engine.py` |
| LLM 语义增强 | `src/vulnagent/analyzers/binary/deobfuscation/semantic.py` |
| 两个专属 Agent | `src/vulnagent/agents/program_restoration_agent.py`、`code_deobfuscation_agent.py` |
| Agent 编排 | `src/vulnagent/agent_runtime/supervisor.py`、`runtime.py` |
| 报告 | `src/vulnagent/report/generator.py`、`html.py`、`pdf.py` |
| 前端 | `src/components/TestLabView.tsx`、`BinaryReverseWorkbench.tsx`、`AgentTopologyView.tsx`、`ReportView.tsx` |

## 11. 验收与指标设计

每个保护家族至少准备“保护样本 + 未保护同源样本”，保存源代码、构建命令、保护工具版本和 SHA-256。推荐指标：

- 识别准确率：正确家族数 / 有标签样本数；
- 恢复成功率：通过严格结构解析且生成派生文件数 / 尝试恢复数；
- 反编译成功率：获得至少一个函数与伪代码的派生文件数 / 恢复文件数；
- IAT 完整率：重建后解析出的预期导入数 / Ground Truth 导入数；
- CFG 边准确率：与未混淆同源程序匹配的边数 / 恢复边数；
- 字符串准确率：正确明文数 / 输出明文数；
- 漏洞审计提升：同源样本还原前后 Recall、Precision、F1 的配对差值；
- 性能：P50/P95 恢复耗时和最大内存。

不能把“工具退出码为 0”当作恢复成功；必须同时记录产物哈希、解析校验、反编译证据和输入/输出关联。

## 12. 运行与测试

```powershell
.\.venv-codex\Scripts\python.exe -m pip install -e ".[test,binary-analysis,report-export]"
.\.venv-codex\Scripts\python.exe -m pytest tests\protected_recovery -q
npm run lint
npm run build
```

动态 Provider 未配置时，仍可演示完整的静态识别、策略选择、失败可解释回退、四类混淆还原、Evidence 和专项报告。需要动态演示时，应在隔离课程 VM 内实现并注入 Provider，绝不能为了展示效果在 FastAPI 主机直接运行上传文件。

## 13. 答辩讲解话术

### 回应“加壳技术老旧”

“原系统基本停留在 UPX 单一静态解包。本次升级首先把保护能力从一个工具扩展成三级体系：一级覆盖 UPX、ASPack、FSG，二级覆盖 PECompact、Upack、NSIS，三级覆盖 VMProtect 演示版和自研教学 VM。识别也不再只看签名，而是联合节区、熵、入口点、导入稀疏度和字符串证据。系统会给出置信度、依据和策略，因此既有覆盖面，也有可解释性。”

### 回应“还原后无法反编译”

“我们把‘内存里看见原代码’和‘得到可被工具加载的 PE’分成两个问题。隔离调试器负责在真实入口附近采集内存和 API 解析轨迹；IAT 模块重新生成 Import Descriptor、ILT、IAT 和 Hint/Name；PE 模块再生成标准 Header、节表、入口点和 Data Directory。最后不是看文件是否写出来，而是用独立 Parser 和反汇编结果双重验收。失败会保留证据并回退，不会显示虚假成功。”

### 回应“混淆还原能力弱”

“原系统只展示符号或高熵信号，现在对应 OLLVM 的四个典型方向分别处理：平坦化用 CFG 和 Dispatcher/状态转移恢复，虚假控制流用可达性和动态边过滤，指令替换只做可证明的代数等价重写，字符串恢复记录算法与 Key 来源。每个函数都能展示 before/after 和转换依据，再由 LLM 做业务语义注释，而不是让模型猜二进制字节。”

### 回应“多智能体只是界面概念”

“新增的两个 Agent 已进入真实 Supervisor 路由。Program Restoration Agent 先生成分类、恢复、结构修复和校验证据；Binary Analysis Agent 只接收通过校验的派生文件；Code Deobfuscation Agent 输出恢复 CFG、字符串和可读性；Verification Agent 仍是唯一能确认漏洞的角色。任何步骤失败都有类型化 Evidence 和自动回退，因此自主决策不是一条写死的演示脚本。”

### 强调创新点

“创新点不是重复造一个脱壳工具，而是把保护识别、恢复策略、结构重建、反编译校验、语义增强和漏洞验证组合成证据驱动的闭环。传统工具通常给出一个 dump；本系统进一步回答它为什么这样还原、产物是否可解析、哪些代码被改变、可读性提高多少，以及该结果如何影响最终漏洞结论。”

### 主动说明边界

“动态执行默认关闭，Provider 未配置就明确显示 `not_configured`。所有样本、映射文件、模拟器和工具版本均进入教学清单；没有授权、没有隔离环境或没有解析验证时，系统不会声称已经完成动态脱壳。这既是合规要求，也是保证实验可复现性的设计。”
