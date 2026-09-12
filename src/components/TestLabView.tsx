import React, { useCallback, useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  ArrowRight,
  Binary,
  Bot,
  Box,
  Check,
  CheckCircle2,
  ChevronRight,
  CircleDot,
  ClipboardCheck,
  Code2,
  FileSearch,
  FileText,
  FileUp,
  Fingerprint,
  FlaskConical,
  Loader2,
  LockKeyhole,
  Play,
  Plus,
  RefreshCw,
  Server,
  ShieldCheck,
  TerminalSquare,
  Trash2,
  Wrench,
  XCircle,
} from "lucide-react";
import {
  AcceptanceOverview,
  BinaryLabTarget,
  LabArchiveResult,
  LabCategory,
  LabRun,
  LLMArchiveResult,
  LLMScanProgress,
  LLMScanResult,
  LLMVulnerabilityType,
  OllamaModelOption,
  UploadResult,
} from "../types.js";
import { useTranslation } from "../i18n.js";
import { protectionMethodLabel, signalCode, uniqueProtectionMethods } from "../protectionMethods.js";

interface TestLabViewProps {
  onOpenTask: (taskId: string) => void;
  onOpenDossier: (taskId: string) => void;
  onLaunchCodeAudit: (path: string, language?: string) => Promise<boolean>;
}

const CATEGORY_COPY: Record<LabCategory, { zh: string; en: string; hintZh: string; hintEn: string }> = {
  local_llm: {
    zh: "开源大模型",
    en: "Open-source LLM",
    hintZh: "Ollama 本地漏洞挖掘 + canary 验证",
    hintEn: "Local Ollama discovery + canary verification",
  },
  packed_binary: {
    zh: "加壳软件",
    en: "Packed Software",
    hintZh: "单个可运行 · 支持多目标批量测试",
    hintEn: "Single or batch authorized PE/ELF/DEX/APK targets",
  },
  obfuscated_binary: {
    zh: "混淆软件",
    en: "Obfuscated Software",
    hintZh: "单个可运行 · 支持多目标批量测试",
    hintEn: "Single or batch authorized PE/ELF/DEX/APK targets",
  },
};

const STATE_CLASS: Record<string, string> = {
  completed: "text-emerald-300 bg-emerald-400/10 border-emerald-400/30",
  partial: "text-amber-300 bg-amber-400/10 border-amber-400/30",
  failed: "text-rose-300 bg-rose-400/10 border-rose-400/30",
  blocked: "text-orange-300 bg-orange-400/10 border-orange-400/30",
  queued: "text-slate-300 bg-white/5 border-white/10",
  running: "text-cyan-300 bg-cyan-400/10 border-cyan-400/30",
  cancelling: "text-amber-300 bg-amber-400/10 border-amber-400/30",
  cancelled: "text-slate-300 bg-slate-400/10 border-slate-400/30",
};

const ACTIVE_STATES = ["queued", "running", "cancelling"];

const LLM_TYPE_OPTIONS: Array<{
  id: LLMVulnerabilityType;
  zh: string;
  en: string;
  count: number;
}> = [
  { id: "prompt_injection", zh: "提示词注入", en: "Prompt injection", count: 5 },
  { id: "system_prompt_leakage", zh: "系统提示词泄露", en: "System prompt leakage", count: 5 },
  { id: "safety_alignment_bypass", zh: "安全对齐绕过", en: "Safety alignment bypass", count: 5 },
];

const LLM_TYPE_LABEL: Record<LLMVulnerabilityType, string> = {
  prompt_injection: "提示词注入",
  system_prompt_leakage: "系统提示词泄露",
  safety_alignment_bypass: "安全对齐绕过",
};

const SAMPLE_PRESETS: Record<"packed_binary" | "obfuscated_binary", Array<{
  label: string;
  name: string;
  path: string;
  protector: string;
  strength: BinaryLabTarget["protection_strength"];
  sha256: string;
}>> = {
  packed_binary: [
    {
      label: "无保护对照",
      name: "benign_cli_plain.exe",
      path: "samples/external_protection_v05/upx_5_2_0/bin/benign_cli_plain.exe",
      protector: "none (local benign baseline)",
      strength: "none",
      sha256: "f70fdedfa7f3ba549f01e115380a59db629d8367e3e0303f7d839180c82b8325",
    },
    {
      label: "一级 UPX",
      name: "benign_cli_upx_5.2.0.exe",
      path: "samples/external_protection_v05/upx_5_2_0/bin/benign_cli_upx_5.2.0.exe",
      protector: "UPX 5.2.0 -9",
      strength: "compression",
      sha256: "df5f4a204b03f7acaeacda3339e7c9e6427a2901715a9bb6c3cebeed256a28d5",
    },
    {
      label: "二级 NSIS 3.12",
      name: "benign_cli_nsis_3.12_setup.exe",
      path: "samples/external_protection_v05/nsis_3_12/bin/benign_cli_nsis_3.12_setup.exe",
      protector: "NSIS 3.12 solid LZMA (project level-2 matrix)",
      strength: "encryption",
      sha256: "2db5a21f5ae1c724423c73d43aadf6182d92ece9e5f25beb6c2c09846ba18de5",
    },
    {
      label: "三级教学 VM",
      name: "teaching_vm_level3.exe",
      path: "samples/external_protection_v05/teaching_vm/bin/teaching_vm_level3.exe",
      protector: "VulnAgent Teaching VM",
      strength: "light_virtualization",
      sha256: "1bcb126a47c29e562a37cc7177bc47be4640509d70e7d990a04a0b433ca6f030",
    },
  ],
  obfuscated_binary: [
    {
      label: "clang14 无混淆对照",
      name: "zlib clang14 O0 baseline",
      path: "samples/external_protection_v05/quarkslab_obfuscation_dataset/zlib/plain/zlib_clang14_x64_O0.exe",
      protector: "none (Quarkslab zlib baseline)",
      strength: "none",
      sha256: "f652bd0737b089e46ae6a0fa5757ba7b4e5168ddf34eca894a7ff6082c12bbec",
    },
    {
      label: "OLLVM 控制流平坦化",
      name: "zlib OLLVM CFF 10%",
      path: "samples/external_protection_v05/quarkslab_obfuscation_dataset/zlib/ollvm14/cff_seed1_o0/zlib_ollvm_clang14_x64_CFF_10_1_O0.exe",
      protector: "OLLVM LLVM-14 CFF 10%",
      strength: "code_obfuscation",
      sha256: "dbbec59f9fb3a9201a1dd403bd2b4717ed5d43683c97dc39bac20086b657253e",
    },
    {
      label: "OLLVM 虚假控制流",
      name: "zlib OLLVM opaque 10%",
      path: "samples/external_protection_v05/quarkslab_obfuscation_dataset/zlib/ollvm14/opaque_seed1_o0/zlib_ollvm_clang14_x64_opaque_10_1_O0.exe",
      protector: "OLLVM LLVM-14 bogus/opaque 10%",
      strength: "code_obfuscation",
      sha256: "5b335017fb2d6e6424caf0484fcaa775b351009062e4a69e22e26cbf5b5f12fc",
    },
    {
      label: "OLLVM 指令替换",
      name: "zlib OLLVM arithmetic 10%",
      path: "samples/external_protection_v05/quarkslab_obfuscation_dataset/zlib/ollvm14/encodearith_seed1_o0/zlib_ollvm_clang14_x64_encodearith_10_1_O0.exe",
      protector: "OLLVM LLVM-14 arithmetic encoding 10%",
      strength: "code_obfuscation",
      sha256: "19ea7765d58f29de04a39368246b1ed42b154a67921f6887d6891623d789379b",
    },
    {
      label: "字符串无混淆对照",
      name: "string_plain.exe",
      path: "samples/external_protection_v05/string_obfuscation/bin/string_plain.exe",
      protector: "none (local string baseline)",
      strength: "none",
      sha256: "13d02e346cd722abfb10a1fc222c44740d942ce4e21899d99da0f395c1875bcf",
    },
    {
      label: "Base64 + XOR 字符串混淆",
      name: "string_xor_base64_obfuscated.exe",
      path: "samples/external_protection_v05/string_obfuscation/bin/string_xor_base64_obfuscated.exe",
      protector: "deterministic Base64 + XOR string fixture",
      strength: "code_obfuscation",
      sha256: "e128cd5c3a11ca2914244e539b47e5ba5f57e36ef703eca27c2f1fb1de1eb6da",
    },
    {
      label: "三级 Tigress VM",
      name: "zlib Tigress virtualization 10%",
      path: "samples/external_protection_v05/quarkslab_obfuscation_dataset/zlib/tigress3/virtualize_seed1_o0/zlib_tigress_gcc_x64_virtualize_10_1_O0.exe",
      protector: "Tigress 3 virtualization 10%",
      strength: "light_virtualization",
      sha256: "11ff5e0d429185f74fb929fd950c6bd827025671a98daf3e2cede66bfc789e14",
    },
  ],
};

const API_FALLBACK_ORIGIN = "http://127.0.0.1:8000";
const nativeFetch = globalThis.fetch.bind(globalThis);

const apiFetch: typeof globalThis.fetch = async (input, init) => {
  try {
    return await nativeFetch(input, init);
  } catch (primaryError) {
    const requestPath = typeof input === "string"
      ? input
      : input instanceof URL
        ? input.toString()
        : "";
    const isLocalPage = typeof window !== "undefined"
      && ["127.0.0.1", "localhost"].includes(window.location.hostname);
    const canUseDirectBackend = primaryError instanceof TypeError
      && isLocalPage
      && requestPath.startsWith("/api/")
      && window.location.origin !== API_FALLBACK_ORIGIN;
    if (!canUseDirectBackend) throw primaryError;
    return nativeFetch(`${API_FALLBACK_ORIGIN}${requestPath}`, init);
  }
};

const apiFailureMessage = (err: unknown, zh: boolean) => {
  if (err instanceof TypeError) {
    return zh
      ? "无法连接本地 API。请确认后端 127.0.0.1:8000 已启动；推荐直接访问该地址，或重新启动 5173 开发前端。"
      : "Cannot reach the local API. Start the backend on :8000 and open that address directly, or restart the Vite server on :5173.";
  }
  return err instanceof Error ? err.message : (zh ? "请求失败" : "Request failed");
};

const newBinary = (index: number): BinaryLabTarget => ({
  name: `Authorized Target ${index + 1}`,
  path: "",
  protector: "",
  protection_strength: "unknown",
  expected_sha256: "",
  authorization_confirmed: false,
  dynamic_validation: false,
  validation_inputs: ["VULNAGENT_LOCAL_TEST"],
});

const TEST_LAB_SESSION_KEY = "vulnagent_test_lab_session_v1";
type BinaryLabCategory = Exclude<LabCategory, "local_llm">;

interface TestLabSessionCache {
  version: 1;
  category: LabCategory;
  selected_model: string;
  selected_llm_types: LLMVulnerabilityType[];
  local_audit_tab: "ai" | "code";
  code_path: string;
  code_language: string;
  code_authorization: boolean;
  binaries: BinaryLabTarget[];
  binary_run_ids: Partial<Record<BinaryLabCategory, string>>;
  llm_scan_id?: string | null;
}

const readTestLabSession = (): TestLabSessionCache | null => {
  if (typeof window === "undefined") return null;
  try {
    const parsed = JSON.parse(window.sessionStorage.getItem(TEST_LAB_SESSION_KEY) || "null");
    return parsed && parsed.version === 1 ? parsed as TestLabSessionCache : null;
  } catch {
    return null;
  }
};

const cachedCategory = (cache: TestLabSessionCache | null): LabCategory =>
  cache && ["local_llm", "packed_binary", "obfuscated_binary"].includes(cache.category)
    ? cache.category
    : "local_llm";

const cachedBinaries = (cache: TestLabSessionCache | null): BinaryLabTarget[] => {
  const items = Array.isArray(cache?.binaries)
    ? cache.binaries.filter((item) => item && typeof item === "object").slice(0, 6)
    : [];
  return items.length
    ? items.map((item, index) => ({
        ...newBinary(index),
        ...item,
        validation_inputs: Array.isArray(item.validation_inputs)
          ? item.validation_inputs.map(String).slice(0, 16)
          : ["VULNAGENT_LOCAL_TEST"],
      }))
    : [newBinary(0)];
};

const cachedLLMTypes = (cache: TestLabSessionCache | null): LLMVulnerabilityType[] => {
  const allowed = new Set(LLM_TYPE_OPTIONS.map((item) => item.id));
  const values = Array.isArray(cache?.selected_llm_types)
    ? cache.selected_llm_types.filter((item) => allowed.has(item))
    : [];
  return values.length ? values : LLM_TYPE_OPTIONS.map((item) => item.id);
};

export const TestLabView: React.FC<TestLabViewProps> = ({ onOpenTask, onOpenDossier, onLaunchCodeAudit }) => {
  const { language } = useTranslation();
  const zh = language === "zh";
  const sessionCache = useMemo(readTestLabSession, []);
  const [category, setCategory] = useState<LabCategory>(() => cachedCategory(sessionCache));
  const [ollamaModels, setOllamaModels] = useState<OllamaModelOption[]>([]);
  const [selectedModel, setSelectedModel] = useState(() => sessionCache?.selected_model || "");
  const [selectedLLMTypes, setSelectedLLMTypes] = useState<LLMVulnerabilityType[]>(
    () => cachedLLMTypes(sessionCache),
  );
  const [localAuditTab, setLocalAuditTab] = useState<"ai" | "code">(
    () => sessionCache?.local_audit_tab === "code" ? "code" : "ai",
  );
  const [codePath, setCodePath] = useState(() => sessionCache?.code_path || "");
  const [codeLanguage, setCodeLanguage] = useState(() => sessionCache?.code_language || "c");
  const [codeAuthorization, setCodeAuthorization] = useState(() => Boolean(sessionCache?.code_authorization));
  const [codeUploading, setCodeUploading] = useState(false);
  const [codeRunning, setCodeRunning] = useState(false);
  const [llmProgress, setLLMProgress] = useState<LLMScanProgress | null>(null);
  const [llmResult, setLLMResult] = useState<LLMScanResult | null>(null);
  const [archiving, setArchiving] = useState(false);
  const [archivingTaskId, setArchivingTaskId] = useState<string | null>(null);
  const [cancelling, setCancelling] = useState(false);
  const [binaries, setBinaries] = useState<BinaryLabTarget[]>(() => cachedBinaries(sessionCache));
  const [run, setRun] = useState<LabRun | null>(null);
  const [binaryRunIds, setBinaryRunIds] = useState<Partial<Record<BinaryLabCategory, string>>>(
    () => sessionCache?.binary_run_ids || {},
  );
  const [llmScanId, setLLMScanId] = useState<string | null>(() => sessionCache?.llm_scan_id || null);
  const [overview, setOverview] = useState<AcceptanceOverview | null>(null);
  const [submittingCategory, setSubmittingCategory] = useState<LabCategory | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [uploading, setUploading] = useState<number | null>(null);
  const [modelsRefreshing, setModelsRefreshing] = useState(false);
  const [modelProbeMessage, setModelProbeMessage] = useState<string | null>(null);

  const loadOllamaModels = useCallback(async () => {
    setModelsRefreshing(true);
    setModelProbeMessage(null);
    try {
      const response = await apiFetch("/api/llm-vulnerability/models");
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const items: OllamaModelOption[] = await response.json();
      setOllamaModels(items);
      setSelectedModel((current) => {
        if (items.some((item) => item.model_name === current && item.installed)) return current;
        return items.find((item) => item.installed)?.model_name || items[0]?.model_name || "";
      });
      const installedCount = items.filter((item) => item.installed).length;
      setModelProbeMessage(
        zh
          ? `探测完成：发现 ${installedCount} 个已安装模型`
          : `Discovery complete: ${installedCount} installed model${installedCount === 1 ? "" : "s"}`,
      );
    } catch {
      setOllamaModels([]);
      const message = zh
        ? "无法读取本地 Ollama 模型列表，请确认 127.0.0.1:11434 已启动。"
        : "Unable to read local Ollama models.";
      setModelProbeMessage(message);
      setError(message);
    } finally {
      setModelsRefreshing(false);
    }
  }, [zh]);

  const loadOverview = useCallback(async () => {
    try {
      const response = await apiFetch("/api/acceptance/overview");
      if (response.ok) setOverview(await response.json());
    } catch {
      // The runnable lab remains usable when the legacy summary is unavailable.
    }
  }, []);

  const selectedBinaryRunId = category === "packed_binary" || category === "obfuscated_binary"
    ? binaryRunIds[category]
    : undefined;

  useEffect(() => {
    try {
      const cache: TestLabSessionCache = {
        version: 1,
        category,
        selected_model: selectedModel,
        selected_llm_types: selectedLLMTypes,
        local_audit_tab: localAuditTab,
        code_path: codePath,
        code_language: codeLanguage,
        code_authorization: codeAuthorization,
        binaries,
        binary_run_ids: binaryRunIds,
        llm_scan_id: llmScanId,
      };
      window.sessionStorage.setItem(TEST_LAB_SESSION_KEY, JSON.stringify(cache));
    } catch {
      // The lab remains usable when browser storage is disabled or full.
    }
  }, [
    category,
    selectedModel,
    selectedLLMTypes,
    localAuditTab,
    codePath,
    codeLanguage,
    codeAuthorization,
    binaries,
    binaryRunIds,
    llmScanId,
  ]);

  useEffect(() => {
    if (!run || (run.category !== "packed_binary" && run.category !== "obfuscated_binary")) return;
    setBinaryRunIds((current) => current[run.category as BinaryLabCategory] === run.run_id
      ? current
      : { ...current, [run.category]: run.run_id });
  }, [run?.run_id, run?.category]);

  useEffect(() => {
    if (category !== "packed_binary" && category !== "obfuscated_binary") return;
    const binaryCategory = category;
    const controller = new AbortController();

    const restoreRun = async () => {
      try {
        let restored: LabRun | null = null;
        if (selectedBinaryRunId) {
          const response = await apiFetch(`/api/test-lab/runs/${selectedBinaryRunId}`, {
            signal: controller.signal,
          });
          if (response.ok) restored = await response.json();
        }
        if (!restored) {
          const response = await apiFetch("/api/test-lab/runs", { signal: controller.signal });
          if (response.ok) {
            const runs: LabRun[] = await response.json();
            restored = runs.find((item) => item.category === binaryCategory) || null;
          }
        }
        if (controller.signal.aborted) return;
        if (!restored) {
          setRun((current) => current?.category === binaryCategory ? current : null);
          return;
        }
        setRun(restored);
        setBinaryRunIds((current) => current[binaryCategory] === restored!.run_id
          ? current
          : { ...current, [binaryCategory]: restored!.run_id });
        setSubmittingCategory((current) => ACTIVE_STATES.includes(restored!.state)
          ? binaryCategory
          : current === binaryCategory ? null : current);
      } catch (err) {
        if (!(err instanceof DOMException && err.name === "AbortError")) {
          // Keep the cached form available when the backend is temporarily offline.
        }
      }
    };

    void restoreRun();
    return () => controller.abort();
  }, [category, selectedBinaryRunId]);

  useEffect(() => {
    if (!llmProgress?.scan_id) return;
    setLLMScanId((current) => current === llmProgress.scan_id ? current : llmProgress.scan_id);
  }, [llmProgress?.scan_id]);

  useEffect(() => {
    if (!llmScanId) return;
    const controller = new AbortController();

    const restoreScan = async () => {
      try {
        const progressResponse = await apiFetch(
          `/api/llm-vulnerability/scans/${llmScanId}/progress`,
          { signal: controller.signal },
        );
        if (progressResponse.status === 404) {
          setLLMScanId(null);
          return;
        }
        if (!progressResponse.ok) return;
        const progress: LLMScanProgress = await progressResponse.json();
        if (controller.signal.aborted) return;
        setLLMProgress(progress);
        if (ACTIVE_STATES.includes(progress.state)) {
          setSubmittingCategory("local_llm");
          return;
        }
        setSubmittingCategory((current) => current === "local_llm" ? null : current);
        const resultResponse = await apiFetch(
          `/api/llm-vulnerability/scans/${llmScanId}/results`,
          { signal: controller.signal },
        );
        if (resultResponse.ok && !controller.signal.aborted) {
          setLLMResult(await resultResponse.json());
        }
      } catch (err) {
        if (!(err instanceof DOMException && err.name === "AbortError")) {
          // Keep the cached scan id for a later retry when the backend returns.
        }
      }
    };

    void restoreScan();
    return () => controller.abort();
  }, [llmScanId]);

  useEffect(() => {
    loadOverview();
    loadOllamaModels();
  }, [loadOverview, loadOllamaModels]);

  useEffect(() => {
    if (!run || !ACTIVE_STATES.includes(run.state)) return;
    const timer = window.setInterval(async () => {
      try {
        const response = await apiFetch(`/api/test-lab/runs/${run.run_id}`);
        if (!response.ok) return;
        const next: LabRun = await response.json();
        setRun(next);
        if (!ACTIVE_STATES.includes(next.state)) {
          setSubmittingCategory((current) => current === next.category ? null : current);
          loadOverview();
        }
      } catch {
        // Keep the current trace visible and try again on the next bounded poll.
      }
    }, 700);
    return () => window.clearInterval(timer);
  }, [run?.run_id, run?.state, loadOverview]);

  useEffect(() => {
    if (!llmProgress || !ACTIVE_STATES.includes(llmProgress.state)) return;
    const timer = window.setInterval(async () => {
      try {
        const response = await apiFetch(`/api/llm-vulnerability/scans/${llmProgress.scan_id}/progress`);
        if (!response.ok) return;
        const next: LLMScanProgress = await response.json();
        setLLMProgress(next);
        if (!ACTIVE_STATES.includes(next.state)) {
          const resultResponse = await apiFetch(`/api/llm-vulnerability/scans/${next.scan_id}/results`);
          if (resultResponse.ok) setLLMResult(await resultResponse.json());
          setSubmittingCategory((current) => current === "local_llm" ? null : current);
          loadOverview();
        }
      } catch {
        // Keep visible evidence and retry the bounded local poll.
      }
    }, 700);
    return () => window.clearInterval(timer);
  }, [llmProgress?.scan_id, llmProgress?.state, loadOverview]);

  const updateBinary = (index: number, patch: Partial<BinaryLabTarget>) => {
    setBinaries((items) => items.map((item, i) => (i === index ? { ...item, ...patch } : item)));
  };

  const uploadBinary = async (index: number, file: File) => {
    setUploading(index);
    setError(null);
    try {
      const response = await apiFetch(
        `/api/uploads?filename=${encodeURIComponent(file.name)}&target_type=binary`,
        { method: "POST", headers: { "Content-Type": "application/octet-stream" }, body: file },
      );
      if (!response.ok) {
        const body = await response.json().catch(() => ({}));
        throw new Error(body.detail || `HTTP ${response.status}`);
      }
      const result: UploadResult = await response.json();
      updateBinary(index, {
        name: file.name,
        path: result.stored_path,
        expected_sha256: result.sha256,
      });
    } catch (err) {
      setError(apiFailureMessage(err, zh));
    } finally {
      setUploading(null);
    }
  };

  const uploadSource = async (file: File) => {
    setCodeUploading(true);
    setError(null);
    try {
      const response = await apiFetch(
        `/api/uploads?filename=${encodeURIComponent(file.name)}&target_type=source`,
        { method: "POST", headers: { "Content-Type": "application/octet-stream" }, body: file },
      );
      if (!response.ok) {
        const body = await response.json().catch(() => ({}));
        throw new Error(body.detail || `HTTP ${response.status}`);
      }
      const result: UploadResult = await response.json();
      setCodePath(result.stored_path);
      setCodeLanguage(result.language || "c");
    } catch (err) {
      setError(apiFailureMessage(err, zh));
    } finally {
      setCodeUploading(false);
    }
  };

  const configuredBinaries = useMemo(
    () => binaries.filter((item) => item.path.trim().length > 0),
    [binaries],
  );

  const binaryValidationError = useMemo(() => {
    if (configuredBinaries.length === 0) {
      return zh
        ? "请至少选择或填写 1 个本地 PE/ELF/DEX/APK 文件后再启动测试。"
        : "Select or enter at least one local PE/ELF/DEX/APK file before starting.";
    }
    const unauthorizedIndex = configuredBinaries.findIndex(
      (item) => !item.authorization_confirmed,
    );
    if (unauthorizedIndex >= 0) {
      return zh
        ? `请先确认目标 ${unauthorizedIndex + 1} 的测试授权。`
        : `Confirm testing authorization for target ${unauthorizedIndex + 1}.`;
    }
    const normalizedPaths = configuredBinaries.map((item) => item.path.trim().toLowerCase());
    if (new Set(normalizedPaths).size !== normalizedPaths.length) {
      return zh ? "批量测试不能重复添加同一路径。" : "Batch targets must use distinct paths.";
    }
    return null;
  }, [configuredBinaries, zh]);

  const canRun = useMemo(() => {
    if (category === "local_llm") {
      if (localAuditTab === "code") {
        return codePath.trim().length > 0 && codeAuthorization;
      }
      return (
        selectedLLMTypes.length > 0 &&
        ollamaModels.some((item) => item.model_name === selectedModel && item.installed)
      );
    }
    return binaryValidationError === null;
  }, [category, localAuditTab, codePath, codeAuthorization, selectedLLMTypes, ollamaModels, selectedModel, binaryValidationError]);

  const visibleRun = run?.category === category ? run : null;
  const currentCategorySubmitting = category === "local_llm" && localAuditTab === "code"
    ? codeRunning
    : submittingCategory === category;
  const currentState = category === "local_llm"
    ? localAuditTab === "ai" ? llmProgress?.state : undefined
    : visibleRun?.state;
  const canCancelCurrent = Boolean(
    currentCategorySubmitting &&
    ACTIVE_STATES.includes(currentState || "") &&
    (category === "local_llm" ? llmProgress?.scan_id : visibleRun?.run_id),
  );

  const startRun = async () => {
    if (submittingCategory !== null) return;
    if (!canRun) {
      setError(
        category === "local_llm"
          ? localAuditTab === "code"
            ? (zh ? "请选择本地 C/C++/Go 源码并确认测试授权。" : "Select local C/C++/Go source and confirm authorization.")
            : (zh
              ? "请选择已安装的本地模型，并至少勾选一种漏洞类型。"
              : "Select an installed local model and at least one vulnerability type.")
          : binaryValidationError,
      );
      return;
    }
    if (category === "local_llm" && localAuditTab === "code") {
      setCodeRunning(true);
      setError(null);
      try {
        await onLaunchCodeAudit(codePath.trim(), codeLanguage);
      } finally {
        setCodeRunning(false);
      }
      return;
    }
    setSubmittingCategory(category);
    setError(null);
    if (category === "local_llm") {
      setLLMProgress(null);
      setLLMResult(null);
      setLLMScanId(null);
      try {
        const response = await apiFetch("/api/llm-vulnerability/scans", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            model_name: selectedModel,
            vulnerability_types: selectedLLMTypes,
          }),
        });
        if (!response.ok) {
          const body = await response.json().catch(() => ({}));
          throw new Error(body.detail || (zh ? "本地模型扫描未能启动" : "Unable to start local scan"));
        }
        const next: LLMScanProgress = await response.json();
        setLLMProgress(next);
        setLLMScanId(next.scan_id);
      } catch (err) {
        setSubmittingCategory(null);
        setError(apiFailureMessage(err, zh));
      }
      return;
    }
    setRun(null);
    const binaryCategory = category as BinaryLabCategory;
    setBinaryRunIds((current) => ({ ...current, [binaryCategory]: undefined }));
    const payload = {
            category,
            name: zh ? "受保护软件授权测试" : "Protected software authorized test",
            binary_targets: configuredBinaries.map((item) => ({
              ...item,
              expected_sha256: item.expected_sha256 || null,
            })),
          };
    try {
      const response = await apiFetch("/api/test-lab/runs", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (!response.ok) {
        const body = await response.json().catch(() => ({}));
        throw new Error(
          typeof body.detail === "string"
            ? body.detail
            : zh
              ? "测试参数未通过后端校验"
              : "The run configuration was rejected",
        );
      }
      const next: LabRun = await response.json();
      setRun(next);
      setBinaryRunIds((current) => ({ ...current, [binaryCategory]: next.run_id }));
    } catch (err) {
      setSubmittingCategory(null);
      setError(apiFailureMessage(err, zh));
    }
  };

  const cancelCurrentRun = async () => {
    if (!canCancelCurrent || cancelling) return;
    setCancelling(true);
    setError(null);
    try {
      if (category === "local_llm" && llmProgress) {
        const response = await apiFetch(
          `/api/llm-vulnerability/scans/${llmProgress.scan_id}/cancel`,
          { method: "POST" },
        );
        if (!response.ok) {
          const body = await response.json().catch(() => ({}));
          throw new Error(body.detail || (zh ? "取消扫描失败" : "Unable to cancel scan"));
        }
        const next: LLMScanProgress = await response.json();
        setLLMProgress(next);
        if (!ACTIVE_STATES.includes(next.state)) {
          const resultResponse = await apiFetch(
            `/api/llm-vulnerability/scans/${next.scan_id}/results`,
          );
          if (resultResponse.ok) setLLMResult(await resultResponse.json());
          setSubmittingCategory(null);
        }
      } else if (visibleRun) {
        const response = await apiFetch(`/api/test-lab/runs/${visibleRun.run_id}/cancel`, {
          method: "POST",
        });
        if (!response.ok) {
          const body = await response.json().catch(() => ({}));
          throw new Error(body.detail || (zh ? "取消测试失败" : "Unable to cancel run"));
        }
        const next: LabRun = await response.json();
        setRun(next);
        if (!ACTIVE_STATES.includes(next.state)) setSubmittingCategory(null);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Cancel failed");
    } finally {
      setCancelling(false);
    }
  };

  const archiveLLMScan = async () => {
    if (!llmProgress || archiving) return;
    if (llmProgress.archived_task_id) {
      onOpenDossier(llmProgress.archived_task_id);
      return;
    }
    setArchiving(true);
    setError(null);
    try {
      const response = await apiFetch(`/api/llm-vulnerability/scans/${llmProgress.scan_id}/archive`, { method: "POST" });
      if (!response.ok) {
        const body = await response.json().catch(() => ({}));
        throw new Error(body.detail || (zh ? "归档失败" : "Archive failed"));
      }
      const archived: LLMArchiveResult = await response.json();
      setLLMProgress((current) => current ? { ...current, archived_task_id: archived.task_id } : current);
      onOpenDossier(archived.task_id);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Archive failed");
    } finally {
      setArchiving(false);
    }
  };

  const archiveBinaryResult = async (taskId: string) => {
    if (!visibleRun || archivingTaskId) return;
    if ((visibleRun.archived_task_ids || []).includes(taskId)) {
      onOpenDossier(taskId);
      return;
    }
    setArchivingTaskId(taskId);
    setError(null);
    try {
      const response = await apiFetch(
        `/api/test-lab/runs/${visibleRun.run_id}/archive/${encodeURIComponent(taskId)}`,
        { method: "POST" },
      );
      if (!response.ok) {
        const body = await response.json().catch(() => ({}));
        throw new Error(body.detail || (zh ? "归档失败" : "Archive failed"));
      }
      const archived: LabArchiveResult = await response.json();
      setRun((current) => current && current.run_id === archived.run_id
        ? { ...current, archived_task_ids: archived.task_ids }
        : current);
      onOpenDossier(taskId);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Archive failed");
    } finally {
      setArchivingTaskId(null);
    }
  };

  const elfBenchmark = overview?.benchmark_summary?.elf_a;

  return (
    <div className="rounded-[28px] overflow-hidden border border-slate-700/70 bg-[#07111f] text-slate-100 shadow-[0_24px_80px_rgba(15,23,42,0.18)]">
      <section className="relative border-b border-white/10 px-5 py-5 sm:px-7 bg-[radial-gradient(circle_at_92%_8%,rgba(34,211,238,0.14),transparent_34%),linear-gradient(135deg,#07111f,#0b1728)]">
        <div className="flex flex-col xl:flex-row xl:items-center justify-between gap-5">
          <div className="flex items-start gap-4">
            <div className="w-12 h-12 rounded-2xl bg-cyan-300 text-slate-950 flex items-center justify-center shadow-[0_0_30px_rgba(103,232,249,0.25)]">
              <FlaskConical className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2 text-[12px] uppercase tracking-[0.22em] font-mono text-cyan-300">
                Local Security Test Lab
                <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
              </div>
              <h1 className="text-2xl sm:text-3xl font-black tracking-tight mt-1">
                {zh ? "三类漏洞测试工作台" : "Three-track vulnerability workbench"}
              </h1>
              <p className="mt-2 text-sm text-slate-400 max-w-3xl leading-relaxed">
                {zh
                  ? "从目标准入、参数配置到过程证据与结果复核，全程只处理本地回环模型和明确授权文件。"
                  : "Configure local loopback models or explicitly authorized files, then inspect every evidence and verification stage."}
              </p>
            </div>
          </div>
          <div className="grid grid-cols-3 gap-2 min-w-[300px]">
            {(overview?.groups ?? []).map((group) => (
              <div key={group.group_id} className="rounded-xl border border-white/10 bg-white/[0.035] px-3 py-2">
                <div className="text-[11px] text-slate-500">{group.group_id.toUpperCase()} · {group.status}</div>
                <div className="text-lg font-bold mt-0.5">{group.group_id === "a" ? "LLM" : group.group_id === "b" ? "PACK" : "OBF"}</div>
              </div>
            ))}
          </div>
        </div>
        <div className="mt-5 grid grid-cols-2 lg:grid-cols-[repeat(3,minmax(0,1fr))_minmax(280px,1.6fr)] gap-2">
          {[
            {
              label: "Source",
              value: overview?.benchmark_summary?.counts.source_samples,
              unit: zh ? "源码样本" : "source samples",
            },
            {
              label: "Binary",
              value: overview?.benchmark_summary?.counts.binary_samples,
              unit: zh ? "二进制样本" : "binary samples",
            },
            {
              label: "Fuzz",
              value: overview?.benchmark_summary?.counts.fuzz_scenarios,
              unit: zh ? "模糊测试场景" : "fuzz scenario",
            },
          ].map((item) => (
            <div key={item.label} className="rounded-xl border border-white/10 bg-black/20 px-3.5 py-3">
              <div className="text-[10px] font-mono uppercase tracking-[0.16em] text-slate-500">{item.label}</div>
              <div className="mt-1 flex items-baseline gap-2">
                <span className="text-2xl font-black text-cyan-200">{item.value ?? "—"}</span>
                <span className="text-[11px] text-slate-500">{item.unit}</span>
              </div>
            </div>
          ))}
          <div className="col-span-2 lg:col-span-1 rounded-xl border border-emerald-400/25 bg-emerald-400/[0.07] px-3.5 py-3">
            <div className="flex items-center justify-between gap-3">
              <div className="text-[10px] font-mono uppercase tracking-[0.16em] text-emerald-300">
                Stripped Binary
              </div>
              <span className="text-[11px] text-slate-400">
                {overview?.benchmark_summary?.stripped_binary
                  ? `${overview.benchmark_summary.stripped_binary.samples} ${zh ? "样本" : "samples"}`
                  : zh ? "指标待生成" : "metrics pending"}
              </span>
            </div>
            {overview?.benchmark_summary?.stripped_binary ? (
              <div className="mt-1.5 flex items-baseline gap-5 font-mono">
                <span className="text-sm text-slate-400">
                  Recall <strong className="text-xl text-emerald-200">{overview.benchmark_summary.stripped_binary.recall.toFixed(3)}</strong>
                </span>
                <span className="text-sm text-slate-400">
                  F1 <strong className="text-xl text-emerald-200">{overview.benchmark_summary.stripped_binary.f1.toFixed(3)}</strong>
                </span>
              </div>
            ) : (
              <p className="mt-2 text-[11px] text-slate-500">
                {zh ? "运行二进制 Benchmark 后在此显示聚合指标。" : "Run the binary benchmark to publish aggregate metrics here."}
              </p>
            )}
          </div>
        </div>
      </section>

      <section className="border-b border-white/10 px-5 py-5 sm:px-7 bg-[#091525]">
        <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 text-[12px] font-mono uppercase tracking-[0.18em] text-violet-300">
              <Binary className="w-4 h-4" />
              ELF-A · {zh ? "真实 ELF Benchmark 看板" : "Real ELF Benchmark Board"}
            </div>
            <p className="mt-1.5 text-[12px] text-slate-400 leading-relaxed">
              {zh
                ? "6 个授权 C Fixture 分别编译为 Symbol-Rich、Stripped、PIE；只读取 ELF，不执行目标。"
                : "Six authorized C fixtures compiled into Symbol-Rich, Stripped and PIE profiles; ELF targets are read, never executed."}
            </p>
          </div>
          {elfBenchmark ? (
            <div className="flex flex-wrap items-center gap-2 text-[11px] font-mono">
              <span className="rounded-lg border border-violet-300/20 bg-violet-300/10 px-2.5 py-1 text-violet-200">{elfBenchmark.fixture_count} FIXTURES</span>
              <span className="rounded-lg border border-violet-300/20 bg-violet-300/10 px-2.5 py-1 text-violet-200">{elfBenchmark.profile_count} PROFILES</span>
              <span className="rounded-lg border border-cyan-300/20 bg-cyan-300/10 px-2.5 py-1 text-cyan-200">{elfBenchmark.row_count} ROWS</span>
              <span className="rounded-lg border border-emerald-300/20 bg-emerald-300/10 px-2.5 py-1 text-emerald-200">
                TARGET EXECUTION = {elfBenchmark.target_execution ? "YES" : "0"}
              </span>
            </div>
          ) : null}
        </div>

        {elfBenchmark ? (
          <div className="mt-4 grid grid-cols-1 lg:grid-cols-3 gap-3">
            {elfBenchmark.profiles.map((profile) => (
              <div key={profile.method} className="rounded-2xl border border-white/10 bg-white/[0.035] p-4">
                <div className="flex items-center justify-between gap-2">
                  <strong className="text-sm text-slate-100">{profile.profile.toUpperCase()}</strong>
                  <span className="text-[11px] font-mono text-slate-500">{profile.samples} {zh ? "样本" : "samples"}</span>
                </div>
                <div className="mt-3 grid grid-cols-3 gap-2 font-mono">
                  {[
                    ["Precision", profile.precision],
                    ["Recall", profile.recall],
                    ["F1", profile.f1],
                  ].map(([label, value]) => (
                    <div key={String(label)} className="rounded-lg bg-black/20 px-2.5 py-2">
                      <div className="text-[10px] text-slate-500">{label}</div>
                      <div className="mt-0.5 text-base font-black text-violet-200">{Number(value).toFixed(3)}</div>
                    </div>
                  ))}
                </div>
                <div className="mt-3 flex flex-wrap gap-x-4 gap-y-1 text-[11px] font-mono text-slate-400">
                  <span>TP/FP/TN/FN {profile.true_positive}/{profile.false_positive}/{profile.true_negative}/{profile.false_negative}</span>
                  <span>Evidence {profile.evidence_chain_coverage.toFixed(3)}</span>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="mt-4 rounded-xl border border-dashed border-white/15 bg-black/15 px-4 py-4 text-[12px] text-slate-500">
            {zh
              ? "尚未检测到 ELF-A 规范产物；运行 ELF Benchmark 后会自动展示 6×3 聚合结果。"
              : "No canonical ELF-A artifact found. The 6×3 aggregate appears automatically after the ELF benchmark runs."}
          </div>
        )}

        {elfBenchmark && (
          <div className="mt-3 text-[10px] font-mono text-slate-500">
            Zig {elfBenchmark.compiler_version || "—"} · {elfBenchmark.compiler_machine || "—"} · {elfBenchmark.family_count} {zh ? "漏洞家族" : "families"}
          </div>
        )}
      </section>

      <div className="grid grid-cols-1 xl:grid-cols-[240px_minmax(0,1fr)] min-h-[720px]">
        <aside className="border-b xl:border-b-0 xl:border-r border-white/10 p-4 bg-black/10">
          <div className="text-[11px] font-mono uppercase tracking-[0.18em] text-slate-500 px-2 mb-3">
            01 · {zh ? "测试入口" : "Test entry"}
          </div>
          <div className="space-y-2">
            {(["local_llm", "packed_binary", "obfuscated_binary"] as LabCategory[]).map((id) => {
              const active = category === id;
              const Icon = id === "local_llm" ? Bot : id === "packed_binary" ? Box : Code2;
              const copy = CATEGORY_COPY[id];
              return (
                <button
                  key={id}
                  onClick={() => { setCategory(id); setError(null); }}
                  className={`w-full text-left rounded-2xl border p-3.5 transition-all ${
                    active
                      ? "border-cyan-300/60 bg-cyan-300/10 shadow-[inset_3px_0_0_#67e8f9]"
                      : "border-white/10 bg-white/[0.025] hover:bg-white/[0.05]"
                  }`}
                >
                  <div className="flex items-center gap-2.5">
                    <Icon className={`w-4 h-4 ${active ? "text-cyan-300" : "text-slate-500"}`} />
                    <span className="text-sm font-bold">{zh ? copy.zh : copy.en}</span>
                    <ChevronRight className="w-3.5 h-3.5 ml-auto text-slate-600" />
                  </div>
                  <p className="text-[12px] text-slate-500 leading-relaxed mt-2 pl-6">{zh ? copy.hintZh : copy.hintEn}</p>
                </button>
              );
            })}
          </div>

          <div className="mt-5 rounded-2xl border border-emerald-400/20 bg-emerald-400/[0.06] p-3.5">
            <div className="flex items-center gap-2 text-emerald-300 text-xs font-bold">
              <LockKeyhole className="w-4 h-4" />
              {zh ? "本地边界已锁定" : "Local boundary locked"}
            </div>
            <p className="text-[12px] text-slate-400 leading-relaxed mt-2">
              {zh
                ? "LLM 仅允许回环地址；二进制默认只读。第 8、9 优先级能力不在本版本中。"
                : "LLMs are loopback-only; binaries are read-only by default. Priority items 8 and 9 remain excluded."}
            </p>
          </div>
        </aside>

        <main className="p-4 sm:p-6 space-y-5 min-w-0">
          <section className="rounded-2xl border border-white/10 bg-white/[0.025] overflow-hidden">
            <div className="flex items-center justify-between gap-3 border-b border-white/10 px-4 py-3.5">
              <div>
                <div className="text-[11px] font-mono uppercase tracking-[0.18em] text-cyan-300">02 · {zh ? "参数配置" : "Configuration"}</div>
                <h2 className="font-bold mt-1">{zh ? CATEGORY_COPY[category].zh : CATEGORY_COPY[category].en}</h2>
              </div>
              <div className="flex flex-col items-end gap-1 text-xs font-mono text-slate-500">
                <span>
                  {category === "local_llm"
                    ? localAuditTab === "ai" ? "LOCAL_ONLY · 15 PROBES" : "LOCAL SOURCE · AST + CFG + TAINT"
                    : "MIN_TARGETS = 1 · BATCH ≤ 6"}
                </span>
                <span className="flex items-center gap-1 text-[10px] text-emerald-300/80" title={zh ? "返回本页面时自动恢复表单，并从后端重新获取最近任务结果" : "Restores this form and reloads the latest run from the backend when you return"}>
                  <RefreshCw className="h-3 w-3" />{zh ? "当前标签页已缓存" : "Session cache enabled"}
                </span>
              </div>
            </div>

            {category === "local_llm" ? (
              <div className="p-4 space-y-4">
                <div className="grid grid-cols-2 gap-1 rounded-xl border border-white/10 bg-black/20 p-1">
                  {([
                    ["ai", zh ? "AI 交互安全" : "AI interaction security", Bot],
                    ["code", zh ? "软件代码安全" : "Software code security", Code2],
                  ] as const).map(([value, label, Icon]) => (
                    <button
                      key={value}
                      type="button"
                      onClick={() => { setLocalAuditTab(value); setError(null); }}
                      className={`flex items-center justify-center gap-2 rounded-lg px-3 py-2.5 text-xs font-bold transition-colors ${localAuditTab === value ? "bg-cyan-300 text-slate-950" : "text-slate-400 hover:bg-white/5 hover:text-slate-100"}`}
                    >
                      <Icon className="h-4 w-4" />{label}
                    </button>
                  ))}
                </div>
                {localAuditTab === "ai" ? (
                  <>
                <div className="grid grid-cols-1 xl:grid-cols-[minmax(0,1fr)_220px] gap-3">
                  <label className="rounded-xl border border-white/10 bg-black/15 p-4 text-xs text-slate-400">
                    <span className="flex items-center gap-2 font-bold text-slate-200 mb-2">
                      <Server className="w-4 h-4 text-cyan-300" />
                      {zh ? "测试目标模型" : "Target model"}
                    </span>
                    <select
                      value={selectedModel}
                      onChange={(event) => setSelectedModel(event.target.value)}
                      className="lab-input w-full font-mono"
                    >
                      {ollamaModels.map((model) => (
                        <option key={model.model_name} value={model.model_name} disabled={!model.installed}>
                          {model.display_name} · {model.installed ? (zh ? "已安装" : "installed") : (zh ? "未安装" : "missing")}
                        </option>
                      ))}
                    </select>
                    <div className="mt-2 font-mono text-[11px] text-slate-500 break-all">
                      {selectedModel || (zh ? "等待本地模型发现" : "Discovering local models")}
                    </div>
                  </label>
                  <div className="rounded-xl border border-emerald-400/20 bg-emerald-400/[0.055] p-4">
                    <div className="flex items-center gap-2 text-xs font-bold text-emerald-300">
                      <LockKeyhole className="w-4 h-4" />127.0.0.1:11434
                    </div>
                    <p className="text-[11px] leading-relaxed text-slate-400 mt-2">
                      {zh ? "固定使用本机 Ollama；不接收 API Key，不访问云端。" : "Fixed to local Ollama; no API key or cloud access."}
                    </p>
                    <button
                      type="button"
                      onClick={() => void loadOllamaModels()}
                      disabled={modelsRefreshing}
                      className="mt-3 inline-flex min-h-9 w-full cursor-pointer items-center justify-center gap-2 rounded-lg border border-cyan-300/25 bg-cyan-300/[0.07] px-3 py-2 text-xs font-bold text-cyan-200 transition-colors hover:border-cyan-200/50 hover:bg-cyan-300/[0.13] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70 disabled:cursor-wait disabled:opacity-70"
                    >
                      <RefreshCw className={`h-3.5 w-3.5 ${modelsRefreshing ? "animate-spin" : ""}`} />
                      {modelsRefreshing
                        ? (zh ? "正在探测本地模型…" : "Discovering local models…")
                        : (zh ? "重新探测模型" : "Refresh models")}
                    </button>
                    {modelProbeMessage && (
                      <p className="mt-2 text-[11px] leading-relaxed text-emerald-200" role="status" aria-live="polite">
                        {modelProbeMessage}
                      </p>
                    )}
                  </div>
                </div>
                <div>
                  <div className="text-xs font-bold text-slate-300 mb-2">{zh ? "漏洞类型（默认全选）" : "Vulnerability types (all selected)"}</div>
                  <div className="grid grid-cols-1 lg:grid-cols-3 gap-2">
                    {LLM_TYPE_OPTIONS.map((item) => {
                      const checked = selectedLLMTypes.includes(item.id);
                      return (
                        <label key={item.id} className={`lab-check ${checked ? "border-cyan-300/35 bg-cyan-300/[0.06]" : ""}`}>
                          <input
                            type="checkbox"
                            checked={checked}
                            onChange={(event) => setSelectedLLMTypes((current) =>
                              event.target.checked
                                ? [...current, item.id]
                                : current.filter((value) => value !== item.id),
                            )}
                          />
                          <span>
                            <strong>{zh ? item.zh : item.en}</strong>
                            <small>{item.count} {zh ? "条合成 canary 用例" : "synthetic canary probes"}</small>
                          </span>
                        </label>
                      );
                    })}
                  </div>
                </div>
                  </>
                ) : (
                  <div className="space-y-4">
                    <div className="rounded-xl border border-cyan-300/20 bg-cyan-300/[0.045] p-4">
                      <div className="flex items-center gap-2 text-sm font-bold text-cyan-200">
                        <FileSearch className="h-4 w-4" />{zh ? "本地源码审计目标" : "Local source audit target"}
                      </div>
                      <p className="mt-2 text-[11px] leading-relaxed text-slate-400">
                        {zh ? "解析 Go/C/C++ 的 AST 与 CFG，追踪 API 参数到敏感操作的污点路径，再由代码审计 Agent 和 VerificationAgent 独立复核。" : "Build Go/C/C++ AST and CFG facts, trace API inputs to sensitive operations, then run bounded agent review and independent verification."}
                      </p>
                      <div className="mt-3 grid grid-cols-1 gap-2 md:grid-cols-[150px_minmax(0,1fr)_auto]">
                        <select value={codeLanguage} onChange={(event) => setCodeLanguage(event.target.value)} className="lab-input font-mono">
                          <option value="c">C</option><option value="cpp">C++</option><option value="go">Go</option>
                        </select>
                        <input value={codePath} onChange={(event) => setCodePath(event.target.value)} className="lab-input min-w-0 font-mono" placeholder={zh ? "本地源码文件/目录，或右侧选择文件" : "Local source file/directory, or choose a file"} />
                        <label className={`lab-secondary-button relative overflow-hidden ${codeUploading ? "cursor-wait opacity-60" : "cursor-pointer"}`}>
                          {codeUploading ? <Loader2 className="h-4 w-4 animate-spin" /> : <FileUp className="h-4 w-4" />}
                          {zh ? "选择源码" : "Choose source"}
                          <input
                            type="file"
                            accept=".c,.h,.cc,.cpp,.cxx,.hpp,.hh,.go,text/plain"
                            disabled={codeUploading}
                            className="absolute inset-0 h-full w-full cursor-pointer opacity-0"
                            onChange={(event) => {
                              const file = event.currentTarget.files?.[0];
                              if (file) void uploadSource(file);
                              event.currentTarget.value = "";
                            }}
                          />
                        </label>
                      </div>
                    </div>
                    <div>
                      <div className="mb-2 text-xs font-bold text-slate-300">{zh ? "代码风险类型（规则库自动启用）" : "Code risk types (rule library enabled)"}</div>
                      <div className="grid grid-cols-2 gap-2 lg:grid-cols-3">
                        {(zh
                          ? ["整数边界异常", "栈/堆缓冲区越界", "数组越界", "输入校验缺失", "空指针/资源泄漏", "接口与配置权限"]
                          : ["Integer boundaries", "Stack/heap buffers", "Array bounds", "Input validation", "Null/resource handling", "Interface/config authorization"]
                        ).map((label) => <div key={label} className="lab-chip justify-center py-2 text-center">{label}</div>)}
                      </div>
                    </div>
                    <label className={`lab-check ${codeAuthorization ? "border-emerald-300/35 bg-emerald-300/[0.05]" : ""}`}>
                      <input type="checkbox" checked={codeAuthorization} onChange={(event) => setCodeAuthorization(event.target.checked)} />
                      <span><strong>{zh ? "我确认该源码属于本地授权教学环境" : "I confirm this source is locally authorized"}</strong><small>{zh ? "仅静态读取；不访问外网，不生成攻击性内容。" : "Read-only static audit; no external network or offensive output."}</small></span>
                    </label>
                    <div className="rounded-xl border border-dashed border-white/15 bg-black/15 p-3 text-[11px] text-slate-500">
                      {zh ? "动态健壮性验证框架已提供回环地址、低权限离线沙箱证明和自动重置约束；未配置沙箱适配器时保持关闭并拒绝作出动态验证声明。" : "The robustness framework enforces loopback, low-privilege offline sandbox attestation, and reset. It stays off until a sandbox adapter is configured."}
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <div className="p-4 space-y-4">
                {binaries.map((target, index) => (
                  <div key={index} className="rounded-xl border border-white/10 bg-black/15 p-4 space-y-3">
                    <div className="flex items-center gap-2">
                      <FileSearch className="w-4 h-4 text-cyan-300" />
                      <span className="text-xs font-mono text-slate-400">TARGET_{String(index + 1).padStart(2, "0")}</span>
                      {binaries.length > 1 && (
                        <button type="button" onClick={() => setBinaries((items) => items.filter((_, i) => i !== index))} className="ml-auto text-slate-600 hover:text-rose-300" aria-label="Remove target">
                          <Trash2 className="w-4 h-4" />
                        </button>
                      )}
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                      <input value={target.name} onChange={(e) => updateBinary(index, { name: e.target.value })} className="lab-input" placeholder={zh ? "软件名称" : "Software name"} />
                      <input value={target.protector || ""} onChange={(e) => updateBinary(index, { protector: e.target.value })} className="lab-input" placeholder={category === "packed_binary" ? (zh ? "壳/保护器" : "Packer / protector") : (zh ? "混淆器/保护器" : "Obfuscator / protector")} />
                      <select
                        value={target.protection_strength || "unknown"}
                        onChange={(e) => updateBinary(index, { protection_strength: e.target.value as BinaryLabTarget["protection_strength"] })}
                        className="lab-input"
                        aria-label={zh ? "样本保护真值标签" : "Sample protection ground-truth label"}
                      >
                        <option value="unknown">{zh ? "未知：由系统自动识别" : "Unknown: let the system classify"}</option>
                        <option value="none">{zh ? "保护强度：无保护" : "Strength: none"}</option>
                        <option value="compression">{zh ? "一级：压缩保护" : "Level 1: compression"}</option>
                        <option value="encryption">{zh ? "二级：加密保护" : "Level 2: encryption"}</option>
                        <option value="light_virtualization">{zh ? "三级：轻量虚拟化" : "Level 3: light virtualization"}</option>
                        <option value="code_obfuscation">{zh ? "代码混淆" : "Code obfuscation"}</option>
                      </select>
                      <p className="md:col-span-2 rounded-lg border border-cyan-300/15 bg-cyan-300/[0.04] px-3 py-2 text-[11px] leading-relaxed text-slate-400">
                        {zh
                          ? "这里是实验 Ground Truth 标签，不会参与识别评分：自己明确知道样本如何生成时才选择等级；普通未知文件选“未知”，让 Agent 根据节区、熵、入口点和导入表独立判断。"
                          : "This is an experiment ground-truth label and is excluded from classifier scoring. Use Unknown unless you know exactly how the sample was produced."}
                      </p>
                      <div className="md:col-span-2 flex gap-2">
                        <input value={target.path} onChange={(e) => updateBinary(index, { path: e.target.value })} className="lab-input flex-1 font-mono min-w-0" placeholder={zh ? "本地 PE/ELF/DEX/APK 路径，或使用右侧上传" : "Local PE/ELF/DEX/APK path, or upload"} />
                        <label className={`lab-secondary-button relative shrink-0 overflow-hidden ${uploading === index ? "cursor-wait opacity-60" : "cursor-pointer"}`}>
                          {uploading === index ? <Loader2 className="w-4 h-4 animate-spin" /> : <FileUp className="w-4 h-4" />}
                          {uploading === index
                            ? (zh ? "正在上传" : "Uploading")
                            : (zh ? "选择文件" : "Choose file")}
                          <input
                            type="file"
                            aria-label={zh ? `为目标 ${index + 1} 选择本地 PE、ELF、DEX 或 APK 文件` : `Choose a local PE, ELF, DEX or APK file for target ${index + 1}`}
                            className="absolute inset-0 z-10 h-full w-full cursor-pointer opacity-0 disabled:cursor-wait"
                            accept=".exe,.dll,.elf,.bin,.dex,.apk,application/x-msdownload,application/vnd.android.package-archive,application/octet-stream"
                            disabled={uploading === index}
                            onChange={(event) => {
                              const file = event.currentTarget.files?.[0];
                              if (file) void uploadBinary(index, file);
                              event.currentTarget.value = "";
                            }}
                          />
                        </label>
                      </div>
                      <input value={target.expected_sha256 || ""} onChange={(e) => updateBinary(index, { expected_sha256: e.target.value.trim() })} className="lab-input md:col-span-2 font-mono" placeholder="SHA-256 (optional; upload fills automatically)" />
                      <div className="md:col-span-2 rounded-xl border border-violet-300/15 bg-violet-300/[0.035] p-3">
                        <div className="text-[10px] font-mono font-bold uppercase tracking-wider text-violet-200">
                          {zh ? "仓库内置教学样本（点击填入，无需上传）" : "Bundled teaching samples (click to fill)"}
                        </div>
                        <div className="mt-2 flex flex-wrap gap-2">
                          {SAMPLE_PRESETS[category as "packed_binary" | "obfuscated_binary"].map((preset) => (
                            <button
                              key={preset.path}
                              type="button"
                              onClick={() => updateBinary(index, {
                                name: preset.name,
                                path: preset.path,
                                protector: preset.protector,
                                protection_strength: preset.strength,
                                expected_sha256: preset.sha256,
                              })}
                              className="rounded-lg border border-violet-300/20 bg-violet-300/[0.06] px-2.5 py-1.5 text-[10px] font-semibold text-violet-100 hover:bg-violet-300/[0.12]"
                            >
                              {preset.label}
                            </button>
                          ))}
                        </div>
                        <p className="mt-2 text-[10px] leading-relaxed text-slate-500">
                          {zh
                            ? "无保护、一级 UPX、二级 NSIS 和三级教学 VM 均已内置；NSIS 是安装器/压缩容器，仅按本项目教学矩阵归入二级。首次验证请关闭动态验证。"
                            : "Baseline, level-1 UPX, level-2 NSIS, and level-3 Teaching VM fixtures are bundled. NSIS is an installer/compressed container categorized as level 2 only by this project's teaching matrix. Keep dynamic validation off for the first run."}
                        </p>
                      </div>
                    </div>
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-2">
                      <label className="lab-check">
                        <input type="checkbox" checked={target.authorization_confirmed} onChange={(e) => updateBinary(index, { authorization_confirmed: e.target.checked, dynamic_validation: e.target.checked ? target.dynamic_validation : false })} />
                        <span><strong>{zh ? "我确认拥有测试授权" : "I confirm testing authorization"}</strong><small>{zh ? "未确认时后端拒绝分析" : "The backend blocks unconfirmed targets"}</small></span>
                      </label>
                      <label className="lab-check">
                        <input type="checkbox" checked={target.dynamic_validation} disabled={!target.authorization_confirmed} onChange={(e) => updateBinary(index, { dynamic_validation: e.target.checked })} />
                        <span><strong>{zh ? "启用受控动态验证" : "Enable controlled dynamic validation"}</strong><small>{zh ? "首次静态验收请关闭；仅在已配置隔离 Provider/模拟器时开启" : "Keep off for initial static validation; enable only with an isolated provider/emulator"}</small></span>
                      </label>
                    </div>
                    {target.dynamic_validation && (
                      <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
                        <input value={target.validation_inputs[0] || ""} onChange={(e) => updateBinary(index, { validation_inputs: [e.target.value] })} className="lab-input w-full font-mono" placeholder={zh ? "无害 stdin 验证输入" : "Benign stdin validation input"} />
                        <input value={target.emulator_serial || ""} onChange={(e) => updateBinary(index, { emulator_serial: e.target.value || null })} className="lab-input w-full font-mono" placeholder={zh ? "DEX 可选：emulator-5554" : "DEX optional: emulator-5554"} />
                      </div>
                    )}
                  </div>
                ))}
                <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                  <p className="text-[11px] leading-relaxed text-slate-500">
                    {zh
                      ? "每次至少 1 个目标即可运行；“支持任意 2 种”表示系统能力与验收覆盖，不要求同一批次强制上传两个文件。"
                      : "A run needs at least one target. Course coverage across two products does not require both files in the same batch."}
                  </p>
                  <button type="button" onClick={() => setBinaries((items) => [...items, newBinary(items.length)])} disabled={binaries.length >= 6} className="lab-secondary-button shrink-0">
                    <Plus className="w-4 h-4" /> {zh ? "添加授权目标" : "Add authorized target"}
                  </button>
                </div>
              </div>
            )}

            <div className="border-t border-white/10 px-4 py-3 flex flex-col sm:flex-row sm:items-center gap-3 justify-between bg-white/[0.02]">
              <div className="flex items-center gap-2 text-xs text-slate-500">
                <ShieldCheck className="w-4 h-4 text-emerald-300" />
                {category === "local_llm"
                  ? localAuditTab === "ai"
                    ? (zh ? "15 条本地 canary 用例；界面只展示判定摘要与响应摘要，不展示测试输入内容。" : "15 local canary probes; the UI shows verdict and response summaries without test inputs.")
                    : (zh ? "源码只读解析；候选风险统一进入证据链、独立复核和漏洞卷宗。" : "Read-only source parsing; candidates flow into evidence, independent verification, and dossiers.")
                  : (zh ? "不包含 API Key；二进制默认只读，动态验证需显式授权。" : "No API keys; binaries are read-only unless dynamic validation is explicitly authorized.")}
              </div>
              <div className="flex flex-wrap items-center justify-end gap-2">
                {canCancelCurrent && (
                  <button
                    type="button"
                    onClick={cancelCurrentRun}
                    disabled={cancelling || currentState === "cancelling"}
                    className="inline-flex items-center justify-center gap-2 rounded-xl border border-rose-300/35 bg-rose-400/10 px-4 py-2.5 text-sm font-bold text-rose-200 hover:bg-rose-400/20 disabled:cursor-wait disabled:opacity-50 transition-colors"
                  >
                    {cancelling || currentState === "cancelling"
                      ? <Loader2 className="w-4 h-4 animate-spin" />
                      : <XCircle className="w-4 h-4" />}
                    {currentState === "cancelling"
                      ? (zh ? "正在取消" : "Cancelling")
                      : (zh ? "取消测试" : "Cancel test")}
                  </button>
                )}
                <button onClick={startRun} disabled={submittingCategory !== null || uploading !== null || codeUploading || codeRunning} className="inline-flex items-center justify-center gap-2 rounded-xl bg-cyan-300 px-5 py-2.5 text-sm font-black text-slate-950 hover:bg-cyan-200 disabled:opacity-35 disabled:cursor-not-allowed transition-colors">
                  {currentCategorySubmitting ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4 fill-current" />}
                  {currentCategorySubmitting
                    ? (zh ? "测试运行中" : "Running")
                    : submittingCategory !== null
                      ? (zh ? "其他测试运行中" : "Another run is active")
                    : category === "local_llm"
                      ? localAuditTab === "ai"
                        ? (zh ? "开始 AI 安全扫描" : "Start AI safety scan")
                        : (zh ? "开始代码安全审计" : "Start code audit")
                      : (zh ? "启动本地授权测试" : "Run local authorized test")}
                </button>
              </div>
            </div>
          </section>

          {error && (
            <div role="alert" className="rounded-xl border border-rose-400/30 bg-rose-400/10 px-4 py-3 text-sm text-rose-200 flex gap-2">
              <AlertTriangle className="w-4 h-4 mt-0.5 shrink-0" /> {error}
            </div>
          )}

          <div className="grid grid-cols-1 2xl:grid-cols-2 gap-5">
            <section className="rounded-2xl border border-white/10 bg-[#050c17] overflow-hidden min-h-[320px]">
              <div className="px-4 py-3.5 border-b border-white/10 flex items-center justify-between">
                <div>
                  <div className="text-[11px] font-mono uppercase tracking-[0.18em] text-cyan-300">03 · {zh ? "过程日志" : "Process log"}</div>
                  <div className="text-sm font-bold mt-1">
                    {category === "local_llm"
                      ? (llmProgress?.scan_id || (zh ? "等待扫描启动" : "Waiting for a scan"))
                      : (visibleRun?.run_id || (zh ? "等待测试启动" : "Waiting for a run"))}
                  </div>
                </div>
                {(category === "local_llm" ? llmProgress : visibleRun) && (
                  <span className={`text-[11px] uppercase font-mono border rounded-full px-2.5 py-1 ${STATE_CLASS[(category === "local_llm" ? llmProgress?.state : visibleRun?.state) || "queued"]}`}>
                    {category === "local_llm" ? llmProgress?.state : visibleRun?.state}
                  </span>
                )}
              </div>
              <div className="p-3 font-mono text-[12px] max-h-[430px] overflow-y-auto space-y-1.5">
                {category === "local_llm" ? !llmProgress ? (
                  <div className="text-slate-600 p-8 text-center"><TerminalSquare className="w-7 h-7 mx-auto mb-3" />{zh ? "扫描后将显示用例编号、阶段状态和实时判定摘要" : "Case IDs, stage status, and verdict summaries will appear here"}</div>
                ) : (
                  <>
                    <div className="h-1.5 rounded-full bg-white/5 overflow-hidden mb-3">
                      <div className="h-full bg-cyan-300 transition-all" style={{ width: `${llmProgress.progress_percent}%` }} />
                    </div>
                    {llmProgress.logs.map((entry) => (
                      <div key={entry.sequence} className="rounded-lg px-2 py-2 hover:bg-white/[0.025] border-b border-white/[0.035]">
                        <div className="grid grid-cols-[72px_76px_1fr] gap-2">
                          <span className="text-slate-600">{new Date(entry.timestamp).toLocaleTimeString([], { hour12: false })}</span>
                          <span className={entry.level === "error" ? "text-rose-300" : entry.level === "warning" ? "text-amber-300" : entry.level === "success" ? "text-emerald-300" : "text-cyan-300"}>[{entry.phase}]</span>
                          <span className="text-slate-300 break-words">{entry.message}</span>
                        </div>
                        {entry.verdict && <div className="mt-1 pl-[150px] text-slate-500"><span className="text-cyan-300">VERDICT › </span>{entry.verdict}</div>}
                      </div>
                    ))}
                  </>
                ) : !visibleRun ? (
                  <div className="text-slate-600 p-8 text-center"><TerminalSquare className="w-7 h-7 mx-auto mb-3" />{zh ? "运行后将在这里显示真实阶段日志" : "Real stage logs will appear here"}</div>
                ) : visibleRun.logs.length === 0 ? (
                  <div className="text-cyan-300 p-6 flex items-center gap-2"><Loader2 className="w-4 h-4 animate-spin" />{zh ? "后端已排队，等待首条事件…" : "Queued; waiting for the first event…"}</div>
                ) : visibleRun.logs.map((entry, index) => (
                  <div key={`${entry.timestamp}-${index}`} className="grid grid-cols-[72px_88px_1fr] gap-2 rounded-lg px-2 py-1.5 hover:bg-white/[0.025]">
                    <span className="text-slate-600">{new Date(entry.timestamp).toLocaleTimeString([], { hour12: false })}</span>
                    <span className={entry.level === "error" ? "text-rose-300" : entry.level === "warning" ? "text-amber-300" : entry.level === "success" ? "text-emerald-300" : "text-cyan-300"}>[{entry.stage}]</span>
                    <span className="text-slate-300 break-words">{entry.target ? `${entry.target} · ` : ""}{entry.message}</span>
                  </div>
                ))}
              </div>
            </section>

            <section className="rounded-2xl border border-white/10 bg-white/[0.025] overflow-hidden min-h-[320px]">
              <div className="px-4 py-3.5 border-b border-white/10 flex items-center justify-between">
                <div>
                  <div className="text-[11px] font-mono uppercase tracking-[0.18em] text-cyan-300">04 · {zh ? "结果输出" : "Results"}</div>
                  <div className="text-sm font-bold mt-1">
                    {category === "local_llm" ? (zh ? "漏洞统计、证据与归档" : "Risk counts, evidence, and archive") : (zh ? "逐目标证据与复核" : "Per-target evidence and verification")}
                  </div>
                </div>
                {category === "local_llm" && llmResult && ["completed", "partial"].includes(llmResult.state) ? (
                  <button onClick={archiveLLMScan} disabled={archiving} className="lab-secondary-button disabled:opacity-40">
                    {archiving ? <Loader2 className="w-4 h-4 animate-spin" /> : <FileText className="w-4 h-4" />}
                    {llmProgress?.archived_task_id ? (zh ? "查看漏洞卷宗" : "View dossier") : (zh ? "归档到漏洞卷宗" : "Archive to dossier")}
                  </button>
                ) : (
                  <button onClick={loadOverview} className="text-slate-500 hover:text-cyan-300" aria-label="Refresh"><RefreshCw className="w-4 h-4" /></button>
                )}
              </div>
              <div className="p-3 space-y-3 max-h-[430px] overflow-y-auto">
                {category === "local_llm" ? !llmResult ? (
                  <div className="text-slate-600 p-8 text-center"><ClipboardCheck className="w-7 h-7 mx-auto mb-3" />{zh ? "扫描完成后展示分级统计与逐条证据" : "Severity counts and evidence appear after scanning"}</div>
                ) : (
                  <>
                    <div className="grid grid-cols-5 gap-2">
                      {[
                        [zh ? "用例" : "Cases", llmResult.summary.total_cases, "text-slate-100"],
                        [zh ? "触发" : "Triggered", llmResult.summary.triggered_count, "text-rose-300"],
                        [zh ? "高危" : "High", llmResult.summary.by_severity.high || 0, "text-rose-300"],
                        [zh ? "中危" : "Medium", llmResult.summary.by_severity.medium || 0, "text-amber-300"],
                        [zh ? "低危" : "Low", llmResult.summary.by_severity.low || 0, "text-cyan-300"],
                      ].map(([label, value, color]) => (
                        <div key={String(label)} className="rounded-lg bg-black/20 border border-white/[0.07] px-2 py-2">
                          <div className="text-[9px] text-slate-600 uppercase">{label}</div>
                          <div className={`font-mono text-lg font-bold mt-0.5 ${color}`}>{value}</div>
                        </div>
                      ))}
                    </div>
                    <div className="flex flex-wrap gap-2">
                      {LLM_TYPE_OPTIONS.map((item) => (
                        <span key={item.id} className="lab-chip">
                          {zh ? item.zh : item.en}: {llmResult.summary.by_vulnerability_type[item.id] || 0}
                        </span>
                      ))}
                      {llmResult.summary.error_count > 0 && <span className="lab-chip text-rose-300">ERROR: {llmResult.summary.error_count}</span>}
                    </div>
                    {llmResult.results.filter((item) => item.verdict !== "not_triggered").map((result) => (
                      <article key={result.case_id} className={`rounded-xl border p-3.5 ${result.verdict === "triggered" ? "border-rose-400/20 bg-rose-400/[0.045]" : "border-amber-400/20 bg-amber-400/[0.04]"}`}>
                        <div className="flex items-start justify-between gap-3">
                          <div>
                            <div className="font-bold text-sm">{result.case_id} · {result.title}</div>
                            <div className="text-[11px] text-slate-500 mt-1">{LLM_TYPE_LABEL[result.vulnerability_type]} · {result.elapsed_ms} ms</div>
                          </div>
                          <span className={`text-[10px] uppercase font-mono border rounded-full px-2 py-0.5 ${result.verdict === "triggered" ? "text-rose-300 border-rose-400/30" : "text-amber-300 border-amber-400/30"}`}>
                            {result.severity} · {result.verdict}
                          </span>
                        </div>
                        <p className="text-xs text-slate-300 mt-3 leading-relaxed">{result.decision_basis}</p>
                        <div className="mt-3 rounded-lg border border-white/[0.07] bg-black/15 p-2 text-[11px] font-mono text-slate-500">
                          <div>{zh ? "响应证据摘要" : "Response evidence summary"} · SHA256 {result.response_sha256}</div>
                          {result.matched_indicators.length > 0 && <div className="mt-1">{zh ? "判定指标" : "Indicators"} · {result.matched_indicators.join(", ")}</div>}
                          <div className="mt-1 text-slate-600">{zh ? "测试输入和原始响应不在界面展示。" : "Test input and raw response are not displayed."}</div>
                        </div>
                      </article>
                    ))}
                    {llmResult.results.every((item) => item.verdict === "not_triggered") && (
                      <div className="rounded-xl border border-emerald-400/20 bg-emerald-400/[0.05] p-4 text-sm text-emerald-200 flex items-center gap-2">
                        <CheckCircle2 className="w-4 h-4" />{zh ? "所选用例均未观察到 canary 泄露。" : "No canary disclosure was observed."}
                      </div>
                    )}
                  </>
                ) : !visibleRun?.results.length ? (
                  <div className="text-slate-600 p-8 text-center"><ClipboardCheck className="w-7 h-7 mx-auto mb-3" />{zh ? "暂无结构化结果" : "No structured result yet"}</div>
                ) : (
                  visibleRun.results.map((result) => (
                    <article key={`${result.target_name}-${result.task_id || result.status}`} className="rounded-xl border border-white/10 bg-black/15 p-3.5">
                      <div className="flex items-start justify-between gap-3">
                        <div className="min-w-0">
                          <div className="flex items-center gap-2">
                            {result.status === "completed" ? <CheckCircle2 className="w-4 h-4 text-emerald-300" /> : <CircleDot className="w-4 h-4 text-amber-300" />}
                            <h3 className="font-bold text-sm truncate">{result.target_name}</h3>
                          </div>
                          {result.sha256 && <div className="text-[11px] font-mono text-slate-600 mt-1 truncate">sha256:{result.sha256}</div>}
                        </div>
                        <span className={`text-[10px] uppercase font-mono border rounded-full px-2 py-0.5 ${STATE_CLASS[result.status]}`}>{result.status}</span>
                      </div>
                      {result.error ? (
                        <div className="text-xs text-rose-300 mt-3">{result.error}</div>
                      ) : (
                        <div className="grid grid-cols-4 gap-2 mt-3">
                          {[
                            [zh ? "发现" : "Findings", result.finding_count],
                            [zh ? "确认" : "Confirmed", result.confirmed_count],
                            [zh ? "证据" : "Evidence", result.evidence_count],
                            [zh ? "报告" : "Report", result.report_available ? "YES" : "N/A"],
                          ].map(([label, value]) => (
                            <div key={String(label)} className="rounded-lg bg-white/[0.035] px-2 py-2">
                              <div className="text-[10px] text-slate-600 uppercase">{label}</div>
                              <div className="font-mono text-sm font-bold mt-0.5">{value}</div>
                            </div>
                          ))}
                        </div>
                      )}
                      {result.discovery.protection_category && (
                        <div className="mt-3 rounded-xl border border-cyan-300/15 bg-cyan-300/[0.04] p-3">
                          <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
                            <div>
                              <div className="text-[10px] font-mono uppercase text-amber-200">{zh ? "样本声明的保护方法" : "Declared protection"}</div>
                              <div className="mt-1 text-xs font-bold text-slate-100">
                                {result.discovery.declared_protection || (zh ? "未声明具体保护器" : "No protector declared")}
                              </div>
                            </div>
                            <span className="w-fit rounded border border-cyan-300/20 bg-cyan-300/10 px-2 py-1 text-[10px] font-mono text-cyan-200">
                              {result.discovery.protection_category === "packed_binary" ? "PACKING" : "OBFUSCATION"}
                            </span>
                          </div>
                          <div className="mt-2 border-t border-white/10 pt-2">
                            <div className="text-[10px] font-mono uppercase text-cyan-300">{zh ? "系统实际观察" : "Observed static evidence"}</div>
                            <div className="mt-1.5 flex flex-wrap gap-1.5">
                              {uniqueProtectionMethods([
                                ...(Array.isArray(result.discovery.observed_protection_methods) ? result.discovery.observed_protection_methods : []),
                                ...(Array.isArray(result.discovery.static_signals) ? result.discovery.static_signals.map(signalCode) : []),
                              ]).length ? (
                                uniqueProtectionMethods([
                                  ...(Array.isArray(result.discovery.observed_protection_methods) ? result.discovery.observed_protection_methods : []),
                                  ...(Array.isArray(result.discovery.static_signals) ? result.discovery.static_signals.map(signalCode) : []),
                                ]).map((method: unknown) => (
                                  <span key={String(method)} className="rounded-full border border-emerald-300/20 bg-emerald-300/[0.06] px-2 py-1 text-[10px] text-emerald-200">
                                    {protectionMethodLabel(method, language)}
                                  </span>
                                ))
                              ) : (
                                <span className="text-[10px] text-slate-500">{zh ? "未观察到可归因的静态信号" : "No attributable static signal observed"}</span>
                              )}
                            </div>
                          </div>
                          <p className="mt-2 text-[10px] text-slate-500">{zh ? "声明信息用于样本归因，只有系统观察项属于本次分析证据。" : "Declarations identify the sample; only observed items are evidence from this run."}</p>
                        </div>
                      )}
                      <div className="mt-3 flex flex-wrap gap-2 text-[11px] text-slate-400">
                        {result.discovery.endpoint_scope && <span className="lab-chip"><Server className="w-3 h-3" />loopback</span>}
                        {result.discovery.expected_cwe_observed !== undefined && <span className="lab-chip"><Fingerprint className="w-3 h-3" />CWE {result.discovery.expected_cwe_observed ? "matched" : "not matched"}</span>}
                        {result.verification.canary_leaked !== undefined && <span className="lab-chip"><LockKeyhole className="w-3 h-3" />canary {result.verification.canary_leaked ? "leaked" : "protected"}</span>}
                        {result.verification.dynamic_validation_requested && <span className="lab-chip"><FlaskConical className="w-3 h-3" />dynamic evidence {result.verification.dynamic_evidence_count || 0}</span>}
                        {result.discovery.reverse_analysis && <span className="lab-chip"><Code2 className="w-3 h-3" />functions {result.discovery.reverse_analysis.function_count || 0}</span>}
                        {result.discovery.reverse_analysis && <span className="lab-chip"><FileSearch className="w-3 h-3" />pseudocode {result.discovery.reverse_analysis.pseudocode_count || 0}</span>}
                        {result.discovery.reverse_analysis?.derived_from_unpack && <span className="lab-chip"><Box className="w-3 h-3" />unpacked copy</span>}
                        {result.discovery.restoration && <span className="lab-chip"><Wrench className="w-3 h-3" />restore {result.discovery.restoration.status}</span>}
                        {result.discovery.restoration?.metrics?.elapsed_ms !== undefined && <span className="lab-chip"><RefreshCw className="w-3 h-3" />{result.discovery.restoration.metrics.elapsed_ms} ms</span>}
                        {result.discovery.deobfuscation?.readability && <span className="lab-chip"><Code2 className="w-3 h-3" />readability {result.discovery.deobfuscation.readability.before || 0}→{result.discovery.deobfuscation.readability.after || 0}</span>}
                      </div>
                      {result.task_id && (
                        <div className="mt-3 flex flex-wrap items-center gap-3">
                          <button onClick={() => onOpenTask(result.task_id!)} className="text-xs font-bold text-cyan-300 hover:text-cyan-200 flex items-center gap-1">
                            {zh ? "打开逆向伪代码、证据与报告" : "Open pseudocode, evidence, and report"}<ArrowRight className="w-3.5 h-3.5" />
                          </button>
                          <button
                            onClick={() => archiveBinaryResult(result.task_id!)}
                            disabled={archivingTaskId === result.task_id}
                            className="lab-secondary-button disabled:opacity-40"
                          >
                            {archivingTaskId === result.task_id
                              ? <Loader2 className="w-4 h-4 animate-spin" />
                              : <FileText className="w-4 h-4" />}
                            {(visibleRun.archived_task_ids || []).includes(result.task_id!)
                              ? (zh ? "查看漏洞卷宗" : "View dossier")
                              : (zh ? "归档到漏洞卷宗" : "Archive to dossier")}
                          </button>
                        </div>
                      )}
                    </article>
                  ))
                )}
              </div>
            </section>
          </div>
        </main>
      </div>
    </div>
  );
};
