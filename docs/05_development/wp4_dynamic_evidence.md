# WP4 — 动态证据：真实 libFuzzer/ASan 闭环

## 目标（开发指导书 WP4 / 8.4）

在授权本地 C 案例上打通一条**真实 libFuzzer + AddressSanitizer 闭环**：
编译 → 种子 corpus → 覆盖引导变异 → 崩溃收集 → 独立重放 → 修复版对照。
VulnAgent 负责授权、预算、哈希、去重、重放与修复配对；libFuzzer/ASan 负责
底层覆盖与异常观察。工具链不可用时诚实记录 `not_run` + 原因，绝不把
Python 指标改名冒充真实插桩覆盖。

## 新增模块

- `src/vulnagent/sandbox/compiler.py`
  - `locate_clang()`：环境变量 `VULNAGENT_CLANG` → 标准安装路径 → PATH。
  - `compile_libfuzzer_target(...)`：clang GNU 驱动 + `-fsanitize=fuzzer,address`
    编译，返回 `CompileResult(compiled / binary_path / engine_version /
    compile_command_hash / reason / stderr)`；工具缺失 → `compiled=False`。
  - Windows ASan 动态运行时 DLL 复制到 exe 旁（否则 STATUS_DLL_NOT_FOUND）。
- `src/vulnagent/fuzz/libfuzzer.py`
  - `parse_libfuzzer_output(stdout, stderr)`：结构化解析 `runs / coverage /
    corpus / sanitizer_kind / crash_signature / stack_hash / artifact_path /
    timed_out / oom`，崩溃与普通非零退出/超时/OOM 分开统计。
  - `RealLibFuzzerEngine(FuzzEngine)`：授权门 → 目标二进制校验 → 沙箱执行 →
    崩溃 artifact 读取（stdout 路径乱码时回退扫描 `crash-*`）→ 独立重放 →
    修复版对照 → Evidence（FUZZ_INPUT / CRASH_LOG / TOOL_RESULT）。
  - 种子复制到隔离 corpus 目录（libFuzzer 会写回 corpus，绝不污染源种子）。
- `src/vulnagent/core/dependencies.py`：`CapabilityBundle.libfuzzer_engine`
  可选字段；`bootstrap.build_tool_registry` 在注入时用真实引擎替换
  FUZZ_EXECUTE 绑定（默认仍为 ControlledFuzzEngine，向后兼容）。
- `experiments/run_real_libfuzzer.py`：可复现闭环实验器。
- `benchmarks/dynamic/libfuzzer/cp_parse/`：自研案例（CWE-121）——
  `vuln.c`（无界栈复制）、`fix.c`（长度检查）、4 个合法/边界种子、
  `manifest.yaml`（编译命令、种子哈希、期望事实）。

## 记录字段（指导书 8.4）

`compile_command_hash, engine_version, seed, corpus_hash, runs, coverage,
crash_input_sha256, sanitizer_kind, stack_hash, replay_count, fixed_outcome`
全部写入 `FuzzResult.metadata` 与 CRASH_LOG Evidence data。

## 实测闭环结果（本机，clang 23.1.2）

```text
crashes: 1
sanitizer_kind: stack-buffer-overflow
crash_input_sha256: 66a2d354b693c0a9488d0a2af5deff4829808f05b572ae0f65d9edfbb39e19c3
stack_hash: 0b628660a7fe13eb
replay_count: 1
fixed_outcome: clean        # 同输入修复版干净退出
```

## 关键环境事实（本机验证，写入文档避免重踩）

1. **必须用 clang（GNU 驱动），不能用 clang-cl**：本机验证 clang-cl 构建
   （无论 `/MT` 还是 `/MD`）的 ASan 对栈/堆访问均无检测输出，GNU 驱动的
   `-fsanitize=address` 正常检测。
2. **必须 `-O0`**：`-O1` 优化会消除被插桩的栈访问，同一溢出输入在 `-O0`
   报 `stack-buffer-overflow`、在 `-O1` 静默通过。
3. **Windows ASan 栈帧无 `in` 关键字**：帧格式为 `#0 0x... (exe+0x...)`，
   栈哈希正则需兼容两种格式。
4. **stdout 路径乱码**：libFuzzer 输出的 artifact 路径含中文目录时经
   Windows 控制台解码损坏，崩溃处理回退扫描 artifact 目录 `crash-*`。
5. **种子安全**：坏种子（如 `\xff\xff` len=65535）本身就是崩溃输入，
   会在种子加载阶段崩溃；种子只放合法/边界输入，且运行期复制到隔离
   corpus 目录。

## 测试

- `tests/unit/test_libfuzzer_engine.py`（10 项）：解析（DONE/崩溃/超时/OOM/
  POSIX 帧）、不可用诚实状态（编译器缺失、未授权、二进制缺失）、
  corpus 哈希确定性。
- `tests/integration/test_real_libfuzzer_loop.py`：clang 可用时真跑完整闭环
  （崩溃→重放→修复对照全字段断言）；不可用时 skip + 显式原因。
- 可复现命令：
  ```bash
  python -m experiments.run_real_libfuzzer --runs 50000 --max-len 64 --seed 7
  ```

## 门禁

- WP4 单元：10/10；集成：1 passed / 1 skipped（工具可用性条件）。
- 全量门禁待 WP4 合并前复跑：目标 714 + 新增（约 12 项）→ 0 回归。
