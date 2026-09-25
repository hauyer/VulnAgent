# 机理分析：三个已知案例（成果线 A）

对应开发指导书成果线 A「已知漏洞 PoC 学习」。以下案例均为**自研教学复刻
fixture**（无真实 CVE 编号、无上游公告），固定版本、入口—调用链—危险操作、
无害复现、修复对照均如实记录。案例卡存于
`benchmarks/historical/case_cards/`。

> **真实案例对照（P0-2）**：真实 CVE 案例卡存于
> `benchmarks/historical/real_cves/`（数据来源：ExploitGym 官方基准的
> 18 个真实 nofuzz 任务，登记见 `benchmarks/exploitgym/`），每卡含
> `cve_id`、`upstream_advisory_url`、`poc_source`、`fixed_commit` 与
> 理论级利用原理分析（不含载荷）：
>
> - `CVE-2023-48183-quickjs.yaml`：QuickJS，CWE-476 NULL 解引用，
>   修复提交 `c4cdd61`（eval 闭包作用域）；
> - `CVE-2021-32132-gpac.yaml`：GPAC，CWE-122 堆越界，修复提交
>   `e74be597`（abst_box 计数校验）；
> - `CVE-2022-23308-libxml2.yaml`：libxml2，CWE-416 UAF，修复提交
>   `652dd12a`（ID/IDREF 规范化与摘除）。
>
> 三案例与自研复刻案例的对照维度：真实案例含上游公告链接与修复提交，
> 机理分析补充了「从触发到越权/代码执行/数据泄露的利用链（理论级）」，
> 满足照片要求 1 的"利用原理分析"；自研复刻案例则以本地可复现的
> 动态/静态证据支撑同一分析框架。

## 1. cp_parse — CWE-121 栈越界（动态证实）

| 项 | 值 |
|---|---|
| 语言 / 类型 | C / 解析器 |
| 入口 | `LLVMFuzzerTestOneInput`（libFuzzer 回调） |
| 调用链 | `LLVMFuzzerTestOneInput → parse_message(data,size) → char out[8]` 循环写入 |
| 危险操作 | 攻击者可控 16 位长度 `len = data[0] | data[1]<<8`，`for i in 0..len-1: out[i] = data[2+i]` 无边界检查 |
| 触发条件 | `len > 8`（任意 payload 使 len∈[9,65535]） |
| 无害复现 | `python -m experiments.run_real_libfuzzer --runs 50000 --max-len 64 --seed 7` → `crashes=1, sanitizer=stack-buffer-overflow, replay_count=1` |
| 修复对照 | `fix.c` 先校验 `len > sizeof(out)` 拒绝；同一崩溃输入重放 `fixed_outcome=clean` |

**根因**：长度字段（2 字节）与目标栈缓冲区（8 字节）的信任边界不匹配，
缺一次长度校验。**修复差异**：入口前置检查而非放大缓冲区——把不可信输入
挡在写操作之前。

## 2. py-cmd-001 — CWE-78 命令注入（静态）

| 项 | 值 |
|---|---|
| 语言 / 类型 | Python / CLI 包装 |
| 入口 | `run_user_command()` |
| 调用链 | `run_user_command → input() → subprocess.run(command, shell=True, text=True)` |
| 危险操作 | `shell=True` + 未净化用户输入拼接命令串 |
| 触发条件 | 输入如 `; id`，shell 解释为多条命令 |
| 无害复现 | `python -m experiments.run_external_scanners` → py-cmd-001 收到 native+semgrep+bandit 融合候选 |
| 修复对照 | `py-cmd-002-clean` 用参数列表 + `shell=False` |

**根因**：把数据当作代码交给 shell。**修复差异**：`shell=False` 消除解释层，
参数数组不经过 shell 拼接。注意修复样本仍触发 Bandit 通用 `subprocess`
告警——这正是 WP8 消融里 clean 样本 FP 的来源（规则级验证无法剔除，
见下节）。

## 3. py-sql-001 — CWE-89 SQL 注入（静态）

| 项 | 值 |
|---|---|
| 语言 / 类型 | Python / 数据访问 |
| 入口 | `find_user(connection)` |
| 调用链 | `find_user → input() → connection.execute(f"SELECT * FROM users WHERE name = '{username}'")` |
| 危险操作 | f-string 把用户输入直接嵌入 SQL 文本 |
| 触发条件 | 输入如 `' OR '1'='1` 改变查询语义 |
| 无害复现 | `python -m experiments.run_external_scanners` → py-sql-001 收到 native SQL 规则候选 |
| 修复对照 | 参数化占位符（数据与代码分离） |

**根因**：语句构造未分离数据与代码。**修复差异**：占位符绑定，DB 驱动负责
转义，不在业务层手工拼接。

## 三个案例的共性机理

1. **信任边界**：三个漏洞都是"把不可信输入当可信数据用"的边界失守
   （长度/命令串/SQL 文本）。
2. **证据链要求**：动态案例（cp_parse）用 Sanitizer+重放+修复对照形成闭环
   证据；静态案例（cmd/sql）用调用链+危险操作定位，仅能给出 CANDIDATE，
   状态由 Verification 层决定（见 `docs/01_architecture/` 状态机）。
3. **修复差异**：都是"入口拦截"而非"出口打补丁"；对照样本保留在基准中
   以测量误报（WP8 消融的 clean 臂）。
