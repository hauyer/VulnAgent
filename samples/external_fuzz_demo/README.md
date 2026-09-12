# VulnAgent V0.4 动态模糊测试演示样本

> 合规范围：本目录只用于北京邮电大学网络空间安全专业课程作业的本地、授权、受控演示。不要把样本上传到公网服务，也不要对未授权目标启用动态执行。

## 1. 可以直接上传的文件

在“大屏 → 基准套件 → 加壳闭源软件测试”中同时添加下面两个目标：

| 目标 | 上传文件 | 验证输入（单行） | 预期现象 |
| --- | --- | --- | --- |
| AFL Training 适配样本 | `bin/afl-training-vulnagent-upx.exe` | `surpriseX!` | 确定性变异删除 `X` 后命中受控异常退出 |
| Google fuzzing 适配样本 | `bin/google-fuzzing-vulnagent-upx.exe` | `FU^Z` | 确定性变异把 `^` 改为 `Z` 后命中受控异常退出 |

二者都是在本机由公开教学源码编译出的 64 位 Windows PE，再用项目自带的 UPX 5.2.1 加壳。没有下载或运行来源不明的现成 EXE。

## 2. 为什么之前显示“动态模糊：未启用”

动态模糊不是根据“文件是否加壳”自动打开的。一个目标只有同时满足下面三个条件才会进入动态阶段：

1. 在目标卡片中勾选“我确认拥有测试授权”；
2. 再勾选“启用受控动态验证”；
3. 静态/逆向阶段先产生可供验证的候选缺陷。

你截图中的 CrackMe 基准在 `benchmarks/obfuscated/manifest.json` 中明确记录了 `dynamic_execution: false`，其授权声明也是“never executes the target”。因此系统把它用于静态逆向展示，而不应为了让按钮变绿而执行它。

## 3. 大屏演示步骤

1. 打开“基准套件”，选择“加壳闭源软件测试”。当前后端要求至少两个不同的二进制目标，所以两个样本要一起添加。
2. 第一行上传 `afl-training-vulnagent-upx.exe`，第二行上传 `google-fuzzing-vulnagent-upx.exe`。
3. 两行都依次勾选“我确认拥有测试授权”和“启用受控动态验证”。
4. 第一行验证输入填写 `surpriseX!`，第二行填写 `FU^Z`。不要加引号，也不要手工输入换行。
5. 开始测试。完成后进入任务详情，展示 `Binary Analysis → Fuzz → Verification → Reviewer → Report` 的证据流。

如果直接选择 `.c` 或 `.cc` 文件，不能触发这条二进制动态链，因为当前入口只接收 PE/ELF。需要演示源码时，可先讲解本目录中的源码，再上传已经编译好的 PE。

## 4. 已完成的本机实测

2026-09-12 使用 V0.4 的 `v03-source` 主链完成整套回归：

- 整体状态：`completed`，2/2 目标完成；
- 每个目标：8 次受控变异执行，生成 8 条运行轨迹和 1 条异常退出证据；
- 每个目标：2 条发现、2 条独立复核确认、结构化报告可用；
- 两个 UPX 文件均通过 `upx -t` 完整性检查；
- Windows 执行器使用 Job Object 限制进程树、CPU 和内存；当前版本**没有**强制网络隔离和文件系统隔离，所以演示环境仍应断网或置于专用虚拟机中。

这里的“异常退出”是为课程流程设计的可控验证信号。它能证明“输入变异 → 运行异常 → 证据入库 → 独立复核 → 报告”链路确实工作，但不等同于证明真实软件可被利用。

## 5. 样本逻辑（新生版）

### AFL Training 样本

上游程序从标准输入读取字符串。当内容变成 `surprise!` 时，上游教学代码会进入故意保留的异常路径。本地适配器把原始内存故障改为退出码 `7`，避免 Windows 弹出错误报告窗口导致超时。

输入 `surpriseX!` 与触发条件只差一个字符。VulnAgent 的固定随机种子会生成一次“删除字节”变异，于是能够稳定复现证据。

### Google fuzzing 样本

上游 `FuzzMe` 检查输入开头是否为 `FUZZ`。本地适配器从标准输入取数据；条件满足时同样返回退出码 `7`。适配器还保留了一个有界调用的 `strcpy` 静态信号，让 Binary Analysis 能先形成候选，再把任务路由给 Fuzz 智能体。

输入 `FU^Z` 只需要一次字节替换即可变成 `FUZZ`，因此结果可重复，适合答辩现场演示。

## 6. 重新构建

在项目根目录运行：

```powershell
.\samples\external_fuzz_demo\build.ps1
```

脚本需要 `gcc`、`g++`，并使用项目中的 `tools/upx/upx-5.2.1-win64/upx.exe`。编译参数为 `-O0 -g -fno-builtin`，目的是让演示用静态信号更容易被分析器观察到。

## 7. 来源、许可证与校验值

- `afl_training/vulnerable.c`：来自 `mykter/afl-training` 的 quickstart，固定提交 `628042ea77a1c0ada826618f77130e4b5d810231`，MIT License。
- `google_fuzzing/fuzz_me.cc`：来自 `google/fuzzing` 的 libFuzzer 教程，固定提交 `734e55f3cfed1adbb51bf6cb5c65b4c1197b7089`，Apache-2.0 License。
- 两份上游许可证均已原样保存在对应子目录中；适配器是本项目为本地课程演示编写的小型入口。

最终上传文件的 SHA-256：

```text
44C1EC721F281B5AD36888BD812ADC3CE18FF99ADB523C14AFDFBD93B83F507D  afl-training-vulnagent-upx.exe
80A2BA552E29FF50675E0AF0BC9E97D039CF8C63ECD4B55075C8D3FB0A31A25D  google-fuzzing-vulnagent-upx.exe
```

机器可读的完整来源和结果记录见 `manifest.json`。

## 8. 现场仍显示“未启用”时

按顺序检查：

1. 是否添加了两个不同路径的 PE；
2. 是否对**每一行**都勾选了授权确认；
3. 是否对**每一行**都勾选了动态验证；
4. 验证输入是否分别为 `surpriseX!` 和 `FU^Z`；
5. 是否使用 `v03-source` 配置，而不是只返回模拟数据的其他配置；
6. 若任务详情完全没有候选缺陷，规划器会合理跳过 Fuzz，而不是盲目执行目标。

当前工作区的 `.venv` 记录的是另一台机器上的 Python 路径，不能直接使用。本机启动后端可用 `py -3.11 -m vulnagent.main`；这不影响已经生成的两个 PE 样本。
