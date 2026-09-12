# VulnAgent V0.5 加壳与混淆实验样本包

生成日期：2026-09-12

本目录依据《VulnAgent V0.5 加壳与混淆还原技术升级方案》整理，目标是给静态识别、还原建议、前后差异验证和教学演示提供一组可追溯的良性样本。样本来自开源项目、官方教学题或本地编译的无害程序；这里没有收集真实恶意软件。

## 先读安全边界

- 默认只做静态分析。不要在日常办公主机上直接运行任何下载所得的 ELF、PE 或 APK。
- 如确需动态验证，PE/ELF 仅放入可还原快照、断网的隔离虚拟机；APK 仅放入本地 `emulator-*`，不要安装到真实设备。
- `xollvm_llvm22` 只提供源码夹具，且故意不启用 VM、反调试或 anti-decompiler 功能。
- 这些材料只用于本项目、课程实验和已授权研究，不用于绕过许可证、访问控制或第三方软件保护。
- 扩展名不等于真实格式：Quarkslab 数据集沿用 `.exe` 文件名，但本包静态检查确认它们实际是 Linux x86-64 ELF。

## 样本矩阵

| 对照组 | 原始样本 | 保护样本 | 保护类型 | 适合验证 |
|---|---|---|---|---|
| `upx-5.2.0-pe` | `upx_5_2_0/bin/benign_cli_plain.exe` | `upx_5_2_0/bin/benign_cli_upx_5.2.0.exe` | UPX 5.2.0，PE x86-64 | 壳识别、UPX0/UPX1/UPX2 节特征、脱壳前后哈希与结构变化 |
| `nsis-3.12-pe` | `upx_5_2_0/bin/benign_cli_plain.exe`（安装器内的良性载荷） | `nsis_3_12/bin/benign_cli_nsis_3.12_setup.exe` | NSIS 3.12 + solid LZMA，PE x86 | 本项目二级矩阵、`.ndata`/Nullsoft/NSIS Error 证据 |
| `teaching-vm-pe` | `teaching_vm/bin/teaching_vm_plain.exe` | `teaching_vm/bin/teaching_vm_level3.exe` | 自建确定性教学 VM，PE x86-64 | 本项目三级矩阵、`.vcode`/`.vmdata`/`vm_dispatch` 证据 |
| `zlib-clang14-cff` | `quarkslab_obfuscation_dataset/zlib/plain/zlib_clang14_x64_O0.exe` | `.../ollvm14/cff_seed1_o0/zlib_ollvm_clang14_x64_CFF_10_1_O0.exe` | OLLVM/LLVM 14，10% 函数 CFF，seed 1，O0 | 控制流平坦化检测与 CFG 还原评估 |
| `zlib-clang14-opaque` | 同一 clang 14 原始件 | `.../ollvm14/opaque_seed1_o0/zlib_ollvm_clang14_x64_opaque_10_1_O0.exe` | OLLVM/LLVM 14，10% 函数 bogus/opaque，seed 1，O0 | 不透明谓词、伪控制流识别 |
| `zlib-clang14-encodearith` | 同一 clang 14 原始件 | `.../ollvm14/encodearith_seed1_o0/zlib_ollvm_clang14_x64_encodearith_10_1_O0.exe` | OLLVM/LLVM 14，10% 函数算术编码，seed 1，O0 | 指令替换、表达式归一化 |
| `string-obfuscation-pe` | `string_obfuscation/bin/string_plain.exe` | `string_obfuscation/bin/string_xor_base64_obfuscated.exe` | 自建 Base64 + 固定 XOR 字符串混淆，PE x86-64 | 字符串加密识别、Base64 明文还原、XOR 证据展示 |
| `zlib-gcc-tigress3-vm` | `quarkslab_obfuscation_dataset/zlib/plain/zlib_gcc_x64_O0.exe` | `.../tigress3/virtualize_seed1_o0/zlib_tigress_gcc_x64_virtualize_10_1_O0.exe` | Tigress 3，10% 函数虚拟化，seed 1，O0 | 虚拟化迹象识别和“检测不等于还原”的分层结果 |
| `owasp-android` | 无一一对应原始 APK | `UnCrackable-Level1.apk`、`UnCrackable-Level2.apk` | OWASP 移动逆向教学题 | APK/DEX 解析、JNI/本地库与反篡改特征演示 |
| `xollvm-llvm22-generator` | `modern_obfuscation_fixture.c` | 由实验者在隔离环境构建 | xollvm LLVM 22：substitution、BCF、flattening、strenc | 面向新 pass manager 的现代源码级样本生成 |

`owasp-android` 不是梆梆、爱加密、乐固或 DexGuard 的已标注真值，不能据此评价这些商业壳的识别准确率。它的用途是验证 APK/DEX 分析链路和教学流程。

## 直接上传清单（按前端选项）

前端点击内置按钮时不需要再次上传；如果使用“选择文件”，就从本目录选择下列文件。`保护强度` 是你已知生成方式时填写的实验真值，不参与系统识别评分。

### 加壳软件

| 要测试的前端选项 | 具体文件名 | 预期静态结果 |
|---|---|---|
| 未知：自动识别 | `nsis_3_12/bin/benign_cli_nsis_3.12_setup.exe` | 系统自行判断 NSIS、level 2；也可把其余任一保护件用“未知”复测 |
| 无保护 | `upx_5_2_0/bin/benign_cli_plain.exe` | 不应命中保护器 |
| 一级：压缩保护 | `upx_5_2_0/bin/benign_cli_upx_5.2.0.exe` | UPX、level 1，置信度 0.92 |
| 二级：加密保护 | `nsis_3_12/bin/benign_cli_nsis_3.12_setup.exe` | NSIS、level 2，置信度 0.85 |
| 三级：轻量虚拟化 | `teaching_vm/bin/teaching_vm_level3.exe` | Teaching VM、level 3，置信度 0.85 |
| 三级对照基线 | `teaching_vm/bin/teaching_vm_plain.exe`，选“无保护” | 不应命中保护器 |

注意：NSIS 本质上是安装器/压缩容器，并不等同于密码学加密壳；这里只因为当前项目的八族教学矩阵把 NSIS 归入 level 2，才在前端选择“二级”。答辩时应按这个准确口径表述。

### 混淆软件

| 混淆类型 | 原始对照文件 | 具体混淆文件 | 前端保护强度 |
|---|---|---|---|
| 控制流平坦化 CFF | `quarkslab_obfuscation_dataset/zlib/plain/zlib_clang14_x64_O0.exe` | `quarkslab_obfuscation_dataset/zlib/ollvm14/cff_seed1_o0/zlib_ollvm_clang14_x64_CFF_10_1_O0.exe` | 对照选“无保护”，混淆件选“代码混淆” |
| 虚假控制流 / 不透明谓词 | 同一 clang 14 原始件 | `quarkslab_obfuscation_dataset/zlib/ollvm14/opaque_seed1_o0/zlib_ollvm_clang14_x64_opaque_10_1_O0.exe` | 代码混淆 |
| 指令替换 / 算术编码 | 同一 clang 14 原始件 | `quarkslab_obfuscation_dataset/zlib/ollvm14/encodearith_seed1_o0/zlib_ollvm_clang14_x64_encodearith_10_1_O0.exe` | 代码混淆 |
| 字符串加密（Base64 + XOR） | `string_obfuscation/bin/string_plain.exe` | `string_obfuscation/bin/string_xor_base64_obfuscated.exe` | 对照选“无保护”，混淆件选“代码混淆” |
| Tigress 函数虚拟化（扩展组） | `quarkslab_obfuscation_dataset/zlib/plain/zlib_gcc_x64_O0.exe` | `quarkslab_obfuscation_dataset/zlib/tigress3/virtualize_seed1_o0/zlib_tigress_gcc_x64_virtualize_10_1_O0.exe` | 轻量虚拟化 |
| APK/DEX 教学链路（非商业壳真值） | 无一一对应基线 | `owasp_mas_crackmes/android/UnCrackable-Level1.apk`、`UnCrackable-Level2.apk` | 未知：自动识别 |

不要把 `.c`、`.nsi`、`.json` 或下载归档 `.zip` 上传给二进制分析入口；这些是源码、构建脚本、真值元数据或工具归档，不是待分析成品。

## 推荐实验顺序

1. 在项目目录运行 `powershell -File samples/external_protection_v05/verify_static.ps1`，只校验文件存在性、SHA-256 与魔数。
2. 依次选择“无保护对照 → 一级 UPX → 二级 NSIS → 三级教学 VM”，确认等级和证据。不要把“识别到保护器”直接记作“脱壳成功”。
3. 对 OLLVM 三组使用相同的 clang 14 原始件作为基线；字符串组使用 `string_plain.exe` 作为基线。
4. 对 Tigress 虚拟化样本只要求“识别迹象 + 给出证据 + 降级说明”；若没有语义等价性证据，不应声称完成还原。
5. APK 只做 ZIP/DEX/清单/本地库的静态检查；若需动态行为，只在本地模拟器中执行。

## 前端“保护强度”如何选择

该字段是实验台账中的 Ground Truth，不参与分类器评分。选择规则如下：

| 前端选项 | 何时选择 | 本包可用样本 |
|---|---|---|
| 未知：由系统自动识别 | 不知道文件怎样生成，或只想测试自主识别 | 任意授权 PE/ELF/DEX/APK |
| 无保护 | 自己编译且没有运行保护工具的基线 | `benign_cli_plain.exe`、`teaching_vm_plain.exe`、`string_plain.exe`、两个 `plain/zlib_*` |
| 一级：压缩保护 | 明确使用 UPX/ASPack/FSG 等压缩壳 | `benign_cli_upx_5.2.0.exe` |
| 二级：加密保护 | 当前项目矩阵中的 PECompact/Upack/NSIS 等实验流程 | `benign_cli_nsis_3.12_setup.exe`；按项目矩阵归类，不宣称 NSIS 是密码学加密壳 |
| 三级：轻量虚拟化 | 明确使用教学 VM 或轻量虚拟化转换 | `teaching_vm_level3.exe`；Tigress 文件作为扩展开源研究组 |
| 代码混淆 | 明确使用 CFF、bogus/opaque、instruction substitution 或 string encryption | 三个 `ollvm14` 变体与 `string_xor_base64_obfuscated.exe` |

首次操作推荐只做静态验收并关闭“受控动态验证”：依次点前端内置的“无保护对照”、
“一级 UPX”、“二级 NSIS”和“三级教学 VM”，分别运行并比较保护归因、恢复状态和反编译结果。动态 Provider
未配置时开启该开关只会得到明确的降级/未配置证据，不会自动获得动态脱壳能力。

其中 UPX 原始/加壳对照是从本包的 `benign_cli.c` 本地编译生成。OLLVM/Tigress
二进制来自已记录来源和哈希的开源差分数据集，不应在答辩中描述为“全部由本组
自行编写”。若课程材料要求所有混淆样本均自研，请用
`xollvm_llvm22/source_fixture/modern_obfuscation_fixture.c` 在隔离构建环境生成四类
变体，并把工具版本、命令与 SHA-256 补入 manifest。

## UPX 5.2.0 受控样本

`benign_cli.c` 是本包自建的确定性、无文件/网络/注册表行为的命令行程序。它由 MinGW-w64 GCC 编译，再使用官方 UPX 5.2.0 Win64 发布件执行：

```powershell
gcc -O0 -fno-builtin .\upx_5_2_0\source\benign_cli.c -o .\upx_5_2_0\bin\benign_cli_plain.exe
.\upx_5_2_0\tool\upx.exe -9 -q -o .\upx_5_2_0\bin\benign_cli_upx_5.2.0.exe .\upx_5_2_0\bin\benign_cli_plain.exe
```

本次生成结果为 `53591 -> 40791` 字节，UPX 报告格式为 `win64/pe`、压缩率为 `76.12%`。静态节表从原始件的常规节变为 `UPX0, UPX1, UPX2`；`upx -t` 对受控加壳件返回 `[OK]`。随包的 `upx.exe` SHA-256 为 `f4c0cc7aca0f1ff0d0b750e966b44139f2fa1a2db7281f48fc52194400712e1d`。

## NSIS 3.12 与三级教学 VM

二级样本由官方 NSIS 3.12 portable 编译器从 `nsis_3_12/source/benign_fixture.nsi` 构建，只封装本包良性基线程序。静态分析命中 `.ndata`、`Nullsoft`、`NSIS Error`，分类为 NSIS/level 2，置信度 0.85。生成时没有运行安装器或其中载荷。

三级样本由 `teaching_vm/source/teaching_vm_fixture.c` 同源构建普通版和 `USE_TEACHING_VM` 版。教学 VM 只解释固定字节码，不接收外部代码，不包含网络、持久化、反调试或注入行为。静态分析命中 `.vcode`、`.vmdata`、`VulnAgent Teaching VM`、`vm_dispatch`，分类为 Teaching VM/level 3，置信度 0.85。

## 字符串混淆夹具

`string_obfuscation/source/string_fixture.c` 同源构建原始/混淆两个 PE。混淆版含确定性 Base64 与固定 XOR 字节数组；当前静态还原引擎已检测 `string_encryption`，并从 Base64 载荷恢复 `VulnAgent deterministic string recovery fixture 2026`。XOR 的键和密文保留为可审计真值；引擎现有合同规定 XOR 自动还原需要分析器把键写入 `metadata.string_decoders`。

## Quarkslab 差分数据集说明

上游完整数据约 92 GB，本包没有整库下载，只取 zlib 的原始包及四个 10% 强度、seed 1、O0 变体。每个混淆目录保留了：

- 可分析二进制；
- 上游函数/符号 JSON；
- 对应的 C 源文件。

这样可以直接构成同项目、同编译器族、同优化级别的对照。上游包只提供 MD5，本包另对每个抽取文件计算了 SHA-256，见 `manifest.json`。

许可证注意：上游 `pyproject.toml` 声明了 `Apache Software License` 分类，源码本身包含 zlib 许可文本，但该提交没有独立的数据集 `LICENSE` 文件。建议限课程内部和授权研究使用；对外再分发前应向数据集作者确认数据归档许可。

## xollvm/LLVM 22 夹具

`xollvm_llvm22/source_fixture/modern_obfuscation_fixture.c` 使用源码注解请求四类 V0.5 关心的转换：指令替换、伪控制流、控制流平坦化和字符串加密。随附上游 `USER.md` 与 `obf_annotations.h`。本包没有下载体量很大的预编译 LLVM 工具链，也没有生成 VM/反调试样本。

## 来源快照

- UPX：官方 v5.2.0 Win64 发布包，2026-06-08；归档 SHA-256 `b471ebf1b7f20f4a89150264ed9a008a2a5bfd247f3c6d1184a75bb59ca08f5d`。
- NSIS：官方 3.12 portable 发布包，2026-04-19；归档 SHA-256 `56581f90db321581c5381193d796fffcf2d24b2f8fed2160a6c6a3baa67f2c4f`。
- Quarkslab `diffing_obfuscation_dataset`：提交 `7d9fc384f2cd2b68220bd811833af32085459c93`，2026-01-15。
- OWASP `mas-crackmes`：提交 `d27a4857b79289cdd88fda423f519f8cd4c42db1`，2022-10-03，LGPL-3.0。
- xollvm：提交 `17afc7ea885538c7724ec8baef566e85cf2878ff`，2026-09-10，Apache-2.0 WITH LLVM-exception。

完整下载 URL、上游归档哈希、样本 SHA-256、格式和架构都记录在 `manifest.json`。
