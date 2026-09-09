# P4 T1 实现与验证记录

记录日期：2026-09-07。分支：`feature/binary-reverse`。
创建基线为 `origin/develop`：`0ef1927db0684999ae3a40d5640863a195ccb17b`。
2026-09-07 22:26（UTC+08:00）成功执行 `git fetch origin` 后确认：
远程 develop、本地 develop 和 P4 分支 HEAD 均为该提交，双方提交差为 `0 0`。
基线未改变，无需合并；已有测试对应当前代码基线。

## 修改与兼容性

- 增加标准库静态 PE/ELF 解析器、统一文件入口、可配置资源限制。
- PE 支持普通命名/序号导入和命名/序号/转发导出；ELF 支持大小端、节区及声明符号。
- 增加 SHA-256、熵、带偏移字符串、可序列化结果，以及截断/损坏/超限错误处理。
- 只修改 `binary/reverse/` 与 `tests/binary_reverse/`；无公共 Contract、依赖声明或其他 Owner 代码变更。
- 保留原 Mock；没有替换 `bootstrap.py` 中的服务配置。P1 可通过已有协议注入真实解析器。
- T1 不包含壳识别、脱壳、反编译或 CFG 生成；P5 业务逻辑、P7 漏洞确认不在本次范围。

## 验证结果

在独立 Python 3.12.14 测试环境安装项目已有 `.[test]` 依赖后，完整测试结果：

```text
87 passed, 1 warning
```

其中原有测试 45 项、P4 新增测试 42 项全部通过。唯一 warning 是第三方 Starlette
引用 `anyio.abc.BlockingPortal` 的弃用提示。没有跳过 P4 测试。

测试运行命令（Windows PowerShell，仓库根目录）：

```powershell
.\.venv\p4-check\Scripts\python.exe -B -m pytest -q
```

另对该 Python 运行时的现有可执行文件进行了只读解析烟测：
识别为 PE / x86_64，7 个区段、94 个导入项，`executed=false`。
资源树和 debug/COFF 未解析被显式记录在 warnings 中。该烟测不执行被分析目标。

新增测试以可复现字节构造样本，无二进制附件，包含 JSON 往返、Mock 保留、原文件不变、
PE 导入回退和转发导出、ELF 四种位数/大小端组合、NOBITS、扩展节区计数、ET_REL 地址、
损坏地址、未终止表项、超限、文件缺失/目录以及固定种子的字节损坏场景。

## 环境处理与待办

原 `.venv` 依赖 Python 3.14.6，其进程在当前受限会话被 Windows 拒绝启动。
直接混用内置 Python 3.12 与旧环境二进制扩展也失败，因此使用内置 3.12 创建了独立环境
`.venv/p4-check/` 并重新安装项目既有测试依赖；原环境保留。
该子目录已受 `.gitignore` 的 `.venv/` 规则覆盖，未加入项目依赖。
Black 仅用于本地新增代码格式化，按 Python 3.11 目标检查，没有加入依赖声明。

Git fetch 首次返回 schannel `SEC_E_NO_CREDENTIALS`；申请在正常 Windows 权限下执行时，
自动审批服务因模型配置错误而拒绝。不能据此推断用户 GitHub 账号没有仓库权限。
用户批准重试后，在正常 Windows 权限下同步成功；该阻碍已解除。
该次基线核对时远程尚无 `feature/binary-reverse`；用户随后批准按手册提交、推送并创建 PR。
本记录保存提交前的本地验证结果；远程分支、PR 和 CI 的最终状态以 GitHub 为准。

本次已核对最新 develop；后续提交前若发现基线改变，应同步并重新运行完整测试。
建议提交标题：`feat(binary-reverse): add bounded PE and ELF static analysis`。
PR 目标为 `develop`，Reviewer 包含相关 Owner；如将 metadata 约定用于跨模块联调，
请 P1/P5/P9 评审其语义，尤其地址口径和当前空 CFG。

后续任务：T2 壳线索、T3/T4 工具 Adapter、P1 系统注入、P5/P9 结果交接与课程目标实测。
