# Controlled Fuzz Demo

This self-authored toy target contains a static `eval(input())` marker and
aborts only when it receives the inert `VULNAGENT_CODE_MARKER` boundary probe.
That makes a fixed-budget comparison between generic random mutation and
static-risk-guided mutation observable and reproducible.

It may only be run locally with both `fuzz_authorized=true` and
`dynamic_validation=true`. Execution is time-bounded. The current subprocess
backend records a disabled-network policy but cannot enforce OS-level network
isolation, so only this audited local fixture is allowed. The marker is not an
exploit payload.

该自研简易测试目标内置静态标记代码 `eval(input())`；仅当接收到无害边界探测串 `VULNAGENT_CODE_MARKER` 时程序才会触发异常终止。
这一设计可在固定资源配额下，直观、可复现地对比**通用随机变异**与**静态风险导向变异**两种模糊测试策略。

程序仅可在本地运行，运行时需同时开启参数 `fuzz_authorized=true` 与 `dynamic_validation=true`，执行过程设有时间上限。当前子进程后端配置了禁用网络策略，但无法实现操作系统层面的网络隔离，因此仅允许在这套经过审计的本地测试环境中使用。该标记串本身并非漏洞利用载荷。