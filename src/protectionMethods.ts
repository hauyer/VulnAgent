type Language = "zh" | "en";

const METHOD_LABELS: Record<string, Record<Language, string>> = {
  high_entropy_section: { zh: "高熵区段", en: "High-entropy section" },
  packer_section_name: { zh: "壳特征区段名", en: "Packer section marker" },
  low_import_count: { zh: "导入表异常精简", en: "Low import count" },
  entry_point_in_high_entropy_section: { zh: "入口点位于高熵区段", en: "Entry point in high-entropy section" },
  anti_debug_import: { zh: "反调试 API", en: "Anti-debug API" },
  packer_marker_string: { zh: "保护器标记字符串", en: "Protector marker string" },
  string_obfuscation: { zh: "编码/高熵字符串", en: "Encoded/high-entropy strings" },
  upx_unpack_copy: { zh: "UPX 副本脱壳", en: "UPX copy unpack" },
  base64_decode: { zh: "Base64 确定性还原", en: "Deterministic Base64 decode" },
  hex_decode: { zh: "十六进制确定性还原", en: "Deterministic hex decode" },
  upx: { zh: "UPX 压缩壳", en: "UPX compression" },
  aspack: { zh: "ASPack 压缩壳", en: "ASPack compression" },
  fsg: { zh: "FSG 压缩壳", en: "FSG compression" },
  pecompact: { zh: "PECompact 加密保护", en: "PECompact protection" },
  upack: { zh: "Upack 加密保护", en: "Upack protection" },
  nsis: { zh: "NSIS 封装", en: "NSIS packaging" },
  vmprotect_demo: { zh: "VMProtect 演示保护", en: "VMProtect demo" },
  teaching_vm: { zh: "教学虚拟机保护", en: "Teaching VM" },
  control_flow_flattening: { zh: "控制流平坦化", en: "Control-flow flattening" },
  bogus_control_flow: { zh: "虚假控制流", en: "Bogus control flow" },
  instruction_substitution: { zh: "指令替换", en: "Instruction substitution" },
  string_encryption: { zh: "字符串加密", en: "String encryption" },
};

export const protectionMethodLabel = (value: unknown, language: Language = "zh"): string => {
  const code = String(value || "unknown");
  return METHOD_LABELS[code]?.[language] || code.replaceAll("_", " ");
};

export const uniqueProtectionMethods = (values: unknown[]): string[] =>
  [...new Set(values.map((value) => String(value || "").trim()).filter(Boolean))];

export const signalCode = (value: unknown): string => {
  if (!value || typeof value !== "object") return "unknown";
  const item = value as Record<string, unknown>;
  return String(item.name || item.kind || item.type || item.signal || "unknown");
};

export const signalEvidence = (value: unknown): string[] => {
  if (!value || typeof value !== "object") return [];
  const evidence = (value as Record<string, unknown>).evidence;
  return Array.isArray(evidence)
    ? evidence.map((item) => String(item)).filter(Boolean).slice(0, 3)
    : [];
};
