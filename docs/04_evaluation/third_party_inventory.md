# 第三方组件登记表（Third-Party Inventory）

> 依据《VulnAgent 漏洞挖掘实践：课程目标完整开发与验收指导书》第 7 节要求登记。
> 每项集成记录 `name/version/source/license/commit_or_digest/role/modified/attribution`。
> 更新日期：2026-09-25。核对人：课程组。

| 名称 | 版本/固定点 | 来源 | 许可证 | 在项目中的角色 | 是否修改 | 归属说明 |
|---|---|---|---|---|---|---|
| ExploitGym | v1.0（git tag） | https://github.com/sunblaze-ucb/exploitgym | 逐任务/数据许可（DATA_LICENSE.md） | 真任务来源；题目卡与 CVE 事实（QuickJS CVE-2023-48183 nofuzz 任务） | 未修改源码；仅浅克隆于 `third_party/exploitgym/` 作登记与事实参考 | 自研盲测协议与评测，不是官方 exploit 评分 |
| QuickJS（上游快照） | 漏洞版 `26fdf659e379a29afb47f1fd46e709b3576645fd`；修复版 `c4cdd61a3ed284cd760faf6b00bbf0cb908da077` | https://github.com/bellard/quickjs（ExploitGym 卡固定提交） | MIT（QuickJS 上游许可证） | 本地盲测目标（CVE-2023-48183）：漏洞/修复版 ASan 二进制 | `quickjs.c` 打 `DISABLE_ATOMICS` Windows 编译补丁（幂等，`_patch_quickjs_win32`）；`main_qjs.c`/`compat/sys/time.h` 为项目自写构建助手 | 构建脚本 `src/vulnagent/benchmark/exploitgym_build.py` 自研 |
| LLVM clang | 23.1.2 | https://llvm.org（官方 Windows 发行） | Apache-2.0（LLVM） | Windows ASan 编译器与运行时（`clang_rt.asan_dynamic-x86_64.dll`、`clang_rt.builtins-x86_64.lib`） | 未修改 | 仅编译工具链；不构成检测能力 |
| Tree-sitter | 按项目已接入版本 | https://tree-sitter.github.io/tree-sitter/ | MIT | 语法树/函数边界底座（静态分析侧） | 未修改 | 自研污点假设与路径摘要 |
| Bandit | 按项目已接入版本 | https://bandit.readthedocs.io/ | Apache-2.0 | 静态信号观察源（外部扫描器，告警标为待验证） | 固定规则集使用 | 告警不直接当最终漏洞；自研融合与复核 |
| libFuzzer / ASan（LLVM） | 随 LLVM 23.1.2 | https://llvm.org/docs/LibFuzzer.html | Apache-2.0（LLVM） | 本地覆盖模糊测试执行器（wp4 自研程序演练） | 未修改 | 自研攻击面选择、种子策略、证据归档 |
| CWE/CVE 数据 | 引用时固定条目 | MITRE/NVD（经 ExploitGym 卡） | 各自许可 | 知识与真值来源 | 未修改 | 知识源不进盲测可见空间 |

## 使用限制与证据纪律

1. 任何第三方工具只提供**观察**，不直接写 `CONFIRMED/REJECTED` 状态；确认只能由独立 Verification 层给出。
2. 盲测 Agent 可见空间（`artifacts/experiments/exploitgym-blind/agent_workspace/`）不挂载 ExploitGym 题卡、CVE 描述、补丁、PoC 或 GT 目录；`LabelLeakageGuard` 在接入前扫描。
3. ExploitGym 题目/补丁/PoC 不对外全量再发布；衍生结果以脱敏摘要与哈希呈现。
4. 固定版本、规则集、commit/digest 均记录于此表与各实验 `build.json`/`checksums.sha256`；工具链失效计 `unavailable`，不计零发现。
