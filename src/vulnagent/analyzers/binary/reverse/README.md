# Binary Reverse（成员 4）

输入 `BinaryAnalysisRequest`，输出 `BinaryAnalysisResult`。负责 PE/ELF、元数据、字符串、导入、函数与基础 CFG。外部工具必须经 Adapter；禁止承担复杂混淆/业务逻辑识别或漏洞确认。测试入口：`pytest tests/contracts tests/binary_reverse`（目录存在时）。

## T1：静态解析实现

`StaticBinaryReverseAnalyzer` 实现已有 `BinaryAnalyzer` 协议，只读取本地普通文件，
不加载或执行目标、不启动工具、不调用模型。`MockBinaryReverseAnalyzer` 保持可用。
公共 `contracts/binary.py` 未变更；服务启动配置仍注入原 Mock，真实解析器的系统接入需 P1 协调。

```python
from vulnagent.contracts import BinaryAnalysisRequest
from vulnagent.analyzers.binary.reverse import StaticBinaryReverseAnalyzer

# 在现有异步入口中调用；path 指向已授权分析的本地文件。
result = await StaticBinaryReverseAnalyzer().analyze(
    BinaryAnalysisRequest(task_id="task-p4", target_id="sample-1", path="sample.exe")
)
payload = result.model_dump_json(indent=2)
```

### 已实现与限制

| 格式 | T1 已实现 | 明确限制 |
| --- | --- | --- |
| PE32 / PE32+ | 魔数、位数、架构、入口、区段、普通命名/序号导入、命名/序号/转发导出 | 不解析延迟导入、资源树、COFF/PDB；不将导出地址冒充函数 |
| ELF32 / ELF64 | 大小端、入口、节区、段范围检查、扩展节区计数、SYMTAB/DYNSYM、导入/导出与声明函数 | 无节区表时不解析 PT_DYNAMIC 符号；不支持符号 SHN_XINDEX，不反汇编 |
| 通用 | SHA-256、文件大小、文件/节区熵、带文件偏移的 ASCII 和 ASCII 范围 UTF-16 LE/BE 字符串 | 字符串是启发式事实，可能重复或误识别，非完整 Unicode 解码 |

`functions` 仅包含 ELF 符号表声明的已定义函数；被剥离符号的函数需要后续反汇编工具。
`cfg` 在 T1 始终为空。壳判定、脱壳、反编译、业务逻辑识别都不能根据 T1 结果宣称已完成。

### 结果约定（metadata_version = 1）

公共字段 `file_format` 为 `PE` 或 `ELF`，`architecture` 为架构名或 `unknown-0x...`。
`imports` 对 PE 使用 `DLL!symbol` / `DLL!#ordinal`，对 ELF 使用未定义动态符号名。
ELF 普通 SYMTAB 的未定义符号不直接当作动态导入。导出中的对象符号不会混入 `functions`。

`metadata` 内保存 `analyzer`、`metadata_version`、`mock=false`、`executed=false`、`sha256`、
`size_bytes`、`bits`、`byte_order`、`entry_point`、`entropy`、`sections`、`exports`、
`string_locations`、`strings_truncated`、`warnings`、`format_details`、`capabilities`。
这是 P4 的附加事实约定；P5/P9 接入前应评审这些 key，不新增公共 Schema 或强制下游依赖。

所有数值地址和偏移均为 JSON 整数。PE `entry_point`/`address` 为首选 ImageBase + RVA，
不是 ASLR 后运行地址；原 RVA 单独保存。ELF 地址为链接时虚拟地址；ET_REL 符号是节区相对地址，
须同时读取 `format_details.address_kind` 和 `section_index`。`offset` 始终表示文件字节偏移。
PE 区段 `size` 为磁盘长度，ELF NOBITS 的 `size=0`、`virtual_size` 为内存长度。

### 资源与错误处理

可注入 `ParseLimits`：默认文件最大 32 MiB、节区/段各最多 4096、符号最多 10000、
符号名称最大 4096 字节、展示字符串最多 4096 条/每条 1024 字节、最短 4 字符。
PE 的导入和导出分别受符号数上限约束；ELF 的所有符号表合计受该上限约束。
展示字符串截断会写入 `strings_truncated` 和 `warnings`，不会静默截断符号表。
不支持、截断、越界、超限或不可读输入统一抛出 `ModuleExecutionError`。

输入总字节数和表项数有界；重复区段扫描超过输入长度时拒绝文件。文件读取/解析使用后台线程，
取消协程不会强杀已启动线程，因此 T1 不承诺硬超时或进程隔离。沙箱和任务时限由调用方提供。
T1 无额外第三方解析依赖；不存在因缺少 Ghidra/UPX 而跳过的核心测试。

### 测试与交接

```powershell
.\.venv\Scripts\python.exe -B -m pytest tests/binary_reverse tests/contracts tests/architecture
.\.venv\Scripts\python.exe -B -m pytest
```

测试在临时目录构造最小 PE/ELF 字节，不提交二进制附件，也不运行样本。
涵盖 PE32/PE32+、ELF32/ELF64 大小端、导入导出、NOBITS、扩展节区编号、损坏引用、
输入限额、序列化、Mock 兼容和原始文件不被修改。验证结果与环境限制见 `T1_VALIDATION.md`。

P1 接入时通过 `BinaryAnalyzer` 注入真实实现；P5 只消费 `BinaryAnalysisResult`。
后续 T2 依据熵、区段和导入事实增加壳线索；T3/T4 接入受控脱壳/反编译 Adapter，
然后再由 P5 做混淆和关键业务逻辑定位。T1 不等同于课程的两类各两个目标验收。
