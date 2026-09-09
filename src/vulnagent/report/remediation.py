"""Small, deterministic remediation guidance used by the report layer.

The public contracts carry no remediation/recommendation field, and the report
module must not read capability internals nor treat model text as an
authoritative confirmation.  This module therefore supplies an internal,
curated set of generic remediation *guidance* (in Chinese) keyed by CWE id or
vulnerability type, plus a generic fallback.  Every block emitted by the report
carries a disclaimer; remediation here never confirms a finding on its own.
"""

import re

CWE_REMEDIATION: dict[str, list[str]] = {
    "CWE-120": [
        "在拷贝/写入前校验长度与目标缓冲区容量，改用带边界检查的拷贝接口。",
        "对源自不受信输入的长度/索引字段先做范围校验，避免绕过边界检查。",
        "启用编译器边界防护（如 ASan）复测，确认越界写入路径已消除。",
    ],
    "CWE-121": [
        "在向栈缓冲区写入前校验长度与容量，改用带边界检查的接口。",
        "复核所有控制循环边界的输入来源，避免长度校验被绕过。",
    ],
    "CWE-122": [
        "为堆缓冲区分配与实际读取/写入量匹配的空间，并在写入前再次校验。",
        "复核长度/偏移计算是否存在溢出或截断导致分配不足。",
    ],
    "CWE-787": [
        "写入前同时校验写入大小与目标缓冲区剩余容量。",
        "对数组下标/偏移做上界与下界双重校验，拒绝负向越界。",
        "优先使用不会越界的容器或安全语言特性，并用边界工具复测。",
    ],
    "CWE-78": [
        "避免将外部输入拼接到系统命令，改用不经 shell 的参数化调用接口。",
        "确需调用 shell 时，对命令与参数建立严格白名单并转义元字符。",
        "以最小权限运行子进程，限制其可访问的文件与网络资源。",
    ],
    "CWE-89": [
        "使用参数化查询/预编译语句，禁止把外部输入拼接进 SQL。",
        "为数据库连接做最小权限划分，不使用高权限账户执行业务查询。",
        "对数据库报错信息脱敏，避免注入探测细节回显给调用方。",
    ],
    "CWE-79": [
        "按输出上下文（HTML/属性/脚本/URL）选择正确的编码接口。",
        "对需保留 HTML 的富文本输入使用白名单清洗。",
        "启用 CSP 等纵深防御，并复核所有受影响渲染路径。",
    ],
    "CWE-22": [
        "先规范化路径并校验其位于允许的根目录内，拒绝 .. 等穿越片段。",
        "基于解析后的规范路径访问文件，避免拼接外部输入后直接使用。",
    ],
    "CWE-502": [
        "避免反序列化不受信数据；如必须使用，限制可反序列化类型白名单。",
        "对序列化载荷增加完整性/签名校验。",
    ],
    "CWE-416": [
        "确保对象在最后一次引用结束前不被释放，使用生命周期管理避免悬挂引用。",
    ],
    "CWE-476": [
        "在解引用前校验指针/引用非空，为可能失败的操作保留错误路径。",
    ],
    "CWE-190": [
        "在运算前校验数值范围，避免溢出/回绕导致边界绕过，必要时使用宽类型或饱和运算。",
    ],
    "CWE-611": [
        "禁用或限制 XML 外部实体解析，关闭外部 DTD 与实体加载。",
        "对解析器做白名单配置，并对解析结果做额外校验。",
    ],
}

TYPE_REMEDIATION: dict[str, list[str]] = {
    "injection": [
        "识别注入点并切换为参数化/白名单接口，禁止拼接外部输入。",
    ],
    "command_injection": [
        "不要将外部输入拼入系统命令，改用参数化调用并以最小权限执行。",
    ],
    "path_traversal": [
        "校验规范化后的路径必须位于允许根目录内，拒绝穿越片段。",
    ],
    "unsafe_deserialization": [
        "避免反序列化不受信数据，必要时限制反序列化类型白名单。",
    ],
}

GENERIC_REMEDIATION: list[str] = [
    "结合具体代码上下文定位根因后做最小化修复，并补充针对触发路径的回归测试。",
    "对不受信输入实施输入校验与最小权限原则，必要时应用边界安全/编码/参数化等对应安全原语。",
    "修复后重新执行验证流程，确认该发现对应的证据链不再成立。",
]

REJECTED_GUIDANCE: list[str] = [
    "该发现已被独立验证排除（rejected），无需修复；若运行环境或输入条件发生变化，建议重新评估。",
]

DISCLAIMER: str = "以上修复建议为通用指引，基于公开的漏洞模式整理，需由开发者结合具体代码上下文复核确认，不构成权威确认。"

_PRIORITY_LABELS: dict[int, str] = {
    0: "P0·紧急",
    1: "P1·高",
    2: "P2·中",
    3: "P3·低",
    4: "P4·信息",
    5: "无需处理",
}

# Non-rejected: severity rank -> urgency code (CRITICAL=P0 ... INFO=P4).
_URGENCY_FROM_RANK: dict[int, int] = {5: 0, 4: 1, 3: 2, 2: 3, 1: 4}
# Statuses whose priority is down-weighted because they are not final.
_UNCONFIRMED_STATUSES = {"candidate", "uncertain"}


def normalize_cwe(cwe_id: str | None) -> str | None:
    """Return a canonical ``CWE-<digits>`` id, or ``None`` for anything else."""
    if not cwe_id:
        return None
    value = str(cwe_id).strip().upper()
    if re.fullmatch(r"CWE-[1-9][0-9]*", value):
        return value
    return None


def guidance_for(
    cwe_id: str | None,
    vulnerability_type: str | None,
    status: str,
) -> tuple[list[str], str]:
    """Return ``(guidance, source_key)`` for a finding.

    ``source_key`` is one of ``rejected``, ``CWE-<digits>``, ``type:<vt>`` or
    ``generic`` so readers can tell where the guidance came from.
    """
    effective = (status or "").lower()
    if effective == "rejected":
        return list(REJECTED_GUIDANCE), "rejected"
    canonical = normalize_cwe(cwe_id)
    if canonical is not None and canonical in CWE_REMEDIATION:
        return list(CWE_REMEDIATION[canonical]), canonical
    vuln_type = (vulnerability_type or "").strip().lower()
    if vuln_type in TYPE_REMEDIATION:
        return list(TYPE_REMEDIATION[vuln_type]), f"type:{vuln_type}"
    return list(GENERIC_REMEDIATION), "generic"


def remediation_priority(severity_rank: int, status: str) -> tuple[int, str]:
    """Return ``(priority_code, chinese_label)``.

    REJECTED findings are not actionable -> ``(5, "无需处理")``.  Otherwise the
    code follows the finding severity (CRITICAL=0 ... INFO/unknown=4) and is
    moved one step less urgent while the status is not final
    (candidate/uncertain).
    """
    effective = (status or "").lower()
    if effective == "rejected":
        return 5, _PRIORITY_LABELS[5]
    code = _URGENCY_FROM_RANK.get(severity_rank, 4)
    if effective in _UNCONFIRMED_STATUSES:
        code = min(4, code + 1)
    return code, _PRIORITY_LABELS[code]
