import React, { useCallback, useEffect, useState } from "react";
import {
  ClipboardCheck,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Play,
  RotateCcw,
  ArrowLeft,
  Gauge,
  Shield,
  Database,
  Server,
  Clock,
  ExternalLink,
  Lock,
  Info,
  Cpu,
  FileSearch,
  Link2,
  FolderOpen,
} from "lucide-react";
import {
  AcceptanceOverview,
  AcceptanceGroup,
  AcceptanceStatus,
  CustomAcceptanceBatch,
  LLMComparisonSummary,
  OllamaModelOption,
  Task,
} from "../types.js";
import { useTranslation } from "../i18n.js";
import { protectionMethodLabel } from "../protectionMethods.js";

const STATUS_STYLES: Record<AcceptanceStatus, string> = {
  pass: "bg-[#edf5d3] text-[#859900] border-[#cce38d]",
  partial: "bg-[#fbf4e6] text-[#b58900] border-[#ecd8a6]",
  fail: "bg-[#fce8e6] text-[#dc322f] border-[#f5b8b5]",
  blocked: "bg-[#fce8e6] text-[#cb4b16] border-[#f5b8b5]",
  not_run: "bg-[#eee8d5] text-[#586e75] border-[#dfd6bf]",
  running: "bg-[#eef4fb] text-[#268bd2] border-[#b9d6f3]",
};

const GROUP_ACCENT: Record<string, string> = {
  a: "from-[#268bd2] to-[#2aa198]",
  b: "from-[#6c71c4] to-[#268bd2]",
  c: "from-[#cb4b16] to-[#b58900]",
};

const GROUP_ICON: Record<string, any> = {
  a: Cpu,
  b: Shield,
  c: FileSearch,
};

export const AcceptanceView: React.FC<{ onOpenTestLab?: () => void }> = ({ onOpenTestLab }) => {
  const { t, language } = useTranslation();
  const [overview, setOverview] = useState<AcceptanceOverview | null>(null);
  const [selectedGroupId, setSelectedGroupId] = useState<string | null>(null);
  const [runningGroupId, setRunningGroupId] = useState<string | null>(null);
  const [runningAll, setRunningAll] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<{ kind: "success" | "error"; text: string } | null>(null);

  const fetchOverview = useCallback(async () => {
    try {
      const res = await fetch("/api/acceptance/overview");
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}`);
      }
      const data: AcceptanceOverview = await res.json();
      setOverview(data);
      setError(null);
    } catch (err) {
      console.error("Failed to load acceptance overview:", err);
      setError(err instanceof Error ? err.message : "Failed to load acceptance overview");
    }
  }, []);

  useEffect(() => {
    const init = async () => {
      setLoading(true);
      await fetchOverview();
      setLoading(false);
    };
    init();
  }, [fetchOverview]);

  const statusLabel = (status: AcceptanceStatus) => t(`accStatus_${status}`);

  const handleRunGroup = async (groupId: string, providers?: string[]) => {
    if (runningGroupId || runningAll) return;
    setRunningGroupId(groupId);
    setNotice(null);
    try {
      const res = await fetch(`/api/acceptance/groups/${groupId}/run`, {
        method: "POST",
        headers: providers ? { "Content-Type": "application/json" } : undefined,
        body: providers ? JSON.stringify({ providers }) : undefined,
      });
      if (!res.ok) {
        let detail = t("accRunFailed");
        try {
          const body = await res.json();
          if (typeof body?.detail === "string") detail = body.detail;
        } catch {
          /* ignore */
        }
        setNotice({ kind: "error", text: detail });
      } else {
        setNotice({ kind: "success", text: t("accRunSuccess") });
      }
      await fetchOverview();
    } catch (err) {
      console.error("Acceptance run failed:", err);
      setNotice({ kind: "error", text: err instanceof Error ? err.message : t("accRunFailed") });
    } finally {
      setRunningGroupId(null);
    }
  };

  const handleRunAll = async () => {
    if (runningAll || runningGroupId) return;
    setRunningAll(true);
    setNotice(null);
    try {
      for (const group of overview?.groups ?? []) {
        const res = await fetch(`/api/acceptance/groups/${group.group_id}/run`, { method: "POST" });
        if (!res.ok && group.group_id !== "b" && group.group_id !== "c") {
          // Only surface group A failures (missing real provider); B/C re-audit is always safe.
          let detail = t("accRunFailed");
          try {
            const body = await res.json();
            if (typeof body?.detail === "string") detail = body.detail;
          } catch {
            /* ignore */
          }
          setNotice({ kind: "error", text: detail });
        }
      }
      await fetchOverview();
      setNotice({ kind: "success", text: t("accRunSuccess") });
    } catch (err) {
      console.error("Acceptance run-all failed:", err);
      setNotice({ kind: "error", text: err instanceof Error ? err.message : t("accRunFailed") });
    } finally {
      setRunningAll(false);
    }
  };

  if (loading) {
    return (
      <div className="p-24 text-center space-y-3 font-mono">
        <div className="w-8 h-8 rounded-full border-2 border-[#2aa198] border-t-transparent animate-spin mx-auto" />
        <p className="text-xs text-[#586e75]">
          {language === "zh" ? "正在计算课程测试验收矩阵..." : "Computing course acceptance matrix..."}
        </p>
      </div>
    );
  }

  if (error && !overview) {
    return (
      <div className="p-16 rounded-2xl bg-[#fcf8ed] border border-[#dfd6bf] text-center space-y-3 shadow-sm">
        <XCircle className="w-8 h-8 text-[#dc322f] mx-auto" />
        <p className="text-sm font-bold text-[#2b3638]">
          {language === "zh" ? "验收矩阵加载失败" : "Failed to load acceptance matrix"}
        </p>
        <p className="text-xs font-mono text-[#586e75]">{error}</p>
      </div>
    );
  }

  if (!overview) return null;

  const selectedGroup: AcceptanceGroup | null = selectedGroupId
    ? overview.groups.find((g) => g.group_id === selectedGroupId) || null
    : null;
  const llmGroup = overview.groups.find((group) => group.group_id === "a") || null;

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="p-5 rounded-2xl bg-[#f4eedb] border border-[#dfd6bf] shadow-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <div className="w-6 h-6 rounded-lg bg-[#2aa198]/10 border border-[#2aa198]/30 flex items-center justify-center text-[#2aa198]">
              <ClipboardCheck className="w-3.5 h-3.5" />
            </div>
            <h2 className="text-base font-bold text-[#2b3638]">{t("accTitle")}</h2>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#eef4fb] text-[#268bd2] border border-[#b9d6f3] font-semibold">
              Honest Acceptance
            </span>
          </div>
          <p className="text-xs text-[#586e75]">{t("accSubtitle")}</p>
        </div>
        <div className="flex items-center gap-2 font-mono text-xs shrink-0">
          <div className="px-3 py-1.5 rounded-lg bg-[#fdfaf3] border border-[#dfd6bf] text-[#2b3638]">
            <Gauge className="w-3.5 h-3.5 inline-block mr-1 text-[#2aa198] -mt-0.5" />
            {t("accOverallStatus")}: <span className="font-bold text-[#2aa198]">{overview.status_text}</span>
          </div>
          <button
            onClick={handleRunAll}
            disabled={runningAll || !!runningGroupId}
            className="px-3 py-1.5 rounded-lg bg-[#2aa198] hover:bg-[#238b83] text-white font-bold flex items-center gap-1.5 transition-colors cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <Play className={`w-3 h-3 fill-current ${runningAll ? "animate-spin" : ""}`} />
            {runningAll ? t("accRunning") : t("accRunAll")}
          </button>
          <button
            onClick={fetchOverview}
            className="p-2 rounded-lg bg-[#fdfaf3] hover:bg-[#ffffff] border border-[#dfd6bf] text-[#586e75] hover:text-[#2b3638] transition-colors cursor-pointer"
            title={t("refresh")}
          >
            <RotateCcw className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Operation Notice */}
      {notice && (
        <div
          className={`px-4 py-3 rounded-xl border text-xs flex items-center gap-2 ${
            notice.kind === "success"
              ? "bg-[#edf5d3] border-[#cce38d] text-[#859900]"
              : "bg-[#fce8e6] border-[#f5b8b5] text-[#dc322f]"
          }`}
        >
          {notice.kind === "success" ? (
            <CheckCircle2 className="w-4 h-4 shrink-0" />
          ) : (
            <AlertTriangle className="w-4 h-4 shrink-0" />
          )}
          <span>{notice.text}</span>
        </div>
      )}

      {/* Group Detail */}
      {selectedGroup ? (
        <GroupDetail
          group={selectedGroup}
          running={runningGroupId === selectedGroup.group_id}
          onRun={(providers) => handleRunGroup(selectedGroup.group_id, providers)}
          onBack={() => setSelectedGroupId(null)}
        />
      ) : (
        <>
          {/* Overview meta strip */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <MetaCard icon={ClipboardCheck} label={t("accPassedGroups")} value={`${overview.passed_groups} / ${overview.total_groups}`} />
            <MetaCard icon={Server} label={t("accCodeVersion")} value={overview.code_version} />
            <MetaCard icon={Database} label={t("accBenchmarkVersion")} value={overview.benchmark_version} />
            <MetaCard icon={Clock} label={t("accGeneratedAt")} value={formatTime(overview.generated_at, language)} />
          </div>

          {/* Benchmark inventory and stripped-binary regression result */}
          <div className="rounded-2xl bg-[#fdfaf3] border border-[#dfd6bf] shadow-sm p-5">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-2 mb-4">
              <div>
                <h3 className="text-sm font-bold text-[#2b3638]">
                  {language === "zh" ? "Benchmark 覆盖与 Stripped 回归" : "Benchmark Coverage & Stripped Regression"}
                </h3>
                <p className="text-[11px] text-[#839496] mt-1">
                  {language === "zh"
                    ? "数量来自仓库清单，指标来自 binary-benchmark 规范产物。"
                    : "Counts come from repository manifests; metrics come from the canonical binary-benchmark artifact."}
                </p>
              </div>
              <span className="text-[10px] font-mono px-2 py-1 rounded bg-[#eee8d5] text-[#586e75] border border-[#dfd6bf]">
                MANIFEST + METRICS.JSON
              </span>
            </div>
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
              {[
                ["Source", overview.benchmark_summary?.counts.source_samples, language === "zh" ? "源码样本" : "source samples"],
                ["Binary", overview.benchmark_summary?.counts.binary_samples, language === "zh" ? "二进制样本" : "binary samples"],
                ["Fuzz", overview.benchmark_summary?.counts.fuzz_scenarios, language === "zh" ? "测试场景" : "test scenario"],
              ].map(([label, value, unit]) => (
                <div key={String(label)} className="rounded-xl border border-[#dfd6bf] bg-[#f8f2e3] px-4 py-3">
                  <div className="text-[10px] font-mono uppercase tracking-[0.14em] text-[#839496]">{label}</div>
                  <div className="mt-1 flex items-baseline gap-2">
                    <span className="text-2xl font-black text-[#2aa198]">{value ?? "—"}</span>
                    <span className="text-[10px] text-[#839496]">{unit}</span>
                  </div>
                </div>
              ))}
              <div className="rounded-xl border border-[#cce38d] bg-[#f4f8e8] px-4 py-3">
                <div className="flex items-center justify-between gap-2">
                  <div className="text-[10px] font-mono uppercase tracking-[0.14em] text-[#859900]">Stripped Binary</div>
                  <span className="text-[10px] text-[#586e75]">
                    {overview.benchmark_summary?.stripped_binary
                      ? `${overview.benchmark_summary.stripped_binary.samples} ${language === "zh" ? "样本" : "samples"}`
                      : language === "zh" ? "待生成" : "pending"}
                  </span>
                </div>
                {overview.benchmark_summary?.stripped_binary ? (
                  <div className="mt-1.5 flex items-baseline gap-4 font-mono text-xs text-[#586e75]">
                    <span>Recall <strong className="text-lg text-[#657b00]">{overview.benchmark_summary.stripped_binary.recall.toFixed(3)}</strong></span>
                    <span>F1 <strong className="text-lg text-[#657b00]">{overview.benchmark_summary.stripped_binary.f1.toFixed(3)}</strong></span>
                  </div>
                ) : (
                  <p className="mt-2 text-[10px] text-[#839496]">
                    {language === "zh" ? "尚无规范指标产物" : "No canonical metric artifact yet"}
                  </p>
                )}
              </div>
            </div>
          </div>

          <LLMUsageOverview group={llmGroup} summary={overview.llm_comparison_summary} />

          <CustomAcceptanceBatchPanel onOpenTestLab={onOpenTestLab} />

          {/* Group Cards */}
          <h3 className="text-sm font-bold text-[#2b3638] flex items-center gap-2">
            <span className="w-1 h-4 rounded bg-[#2aa198]" />
            {t("accGroupsTitle")}
          </h3>
          <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
            {overview.groups.map((group) => (
              <GroupCard
                key={group.group_id}
                group={group}
                running={runningGroupId === group.group_id}
                onOpen={() => setSelectedGroupId(group.group_id)}
                onRun={() => handleRunGroup(group.group_id)}
              />
            ))}
          </div>

          {/* Honest boundaries */}
          {overview.notices.length > 0 && (
            <div className="p-5 rounded-2xl bg-[#fdfaf3] border border-[#dfd6bf] shadow-sm space-y-2">
              <h4 className="text-xs font-bold text-[#2b3638] flex items-center gap-1.5">
                <Info className="w-3.5 h-3.5 text-[#268bd2]" />
                {t("accNoticesTitle")}
              </h4>
              {overview.notices.map((note, index) => (
                <p key={index} className="text-xs text-[#586e75] leading-relaxed flex gap-2">
                  <span className="text-[#2aa198] font-mono shrink-0">·</span>
                  <span>{note}</span>
                </p>
              ))}
            </div>
          )}
        </>
      )}
    </div>
  );
};

const CustomAcceptanceBatchPanel: React.FC<{ onOpenTestLab?: () => void }> = ({ onOpenTestLab }) => {
  const { language } = useTranslation();
  const [tasks, setTasks] = useState<Task[]>([]);
  const [models, setModels] = useState<OllamaModelOption[]>([]);
  const [batches, setBatches] = useState<CustomAcceptanceBatch[]>([]);
  const [batchName, setBatchName] = useState("");
  const [selectedModels, setSelectedModels] = useState<string[]>([]);
  const [selectedPacked, setSelectedPacked] = useState<string[]>([]);
  const [selectedObfuscated, setSelectedObfuscated] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState<{ kind: "success" | "error"; text: string } | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [taskResponse, batchResponse, modelResponse] = await Promise.all([
        fetch("/api/tasks"),
        fetch("/api/acceptance/batches"),
        fetch("/api/llm-vulnerability/models").catch(() => null),
      ]);
      if (!taskResponse.ok || !batchResponse.ok) throw new Error("关联数据加载失败");
      setTasks(await taskResponse.json());
      setBatches(await batchResponse.json());
      setModels(modelResponse?.ok ? await modelResponse.json() : []);
    } catch (error) {
      setMessage({
        kind: "error",
        text: error instanceof Error ? error.message : "关联数据加载失败",
      });
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const category = (task: Task) => String(
    task.target.metadata?.test_lab_category || task.metadata?.test_lab_category || "",
  );
  const modelName = (task: Task) => String(
    task.target.metadata?.model_name || task.metadata?.model_name || "",
  );
  const packedTasks = tasks.filter((task) => category(task) === "packed_binary");
  const obfuscatedTasks = tasks.filter((task) => category(task) === "obfuscated_binary");
  const archivedModels = tasks.map(modelName).filter(Boolean);
  const modelChoices = Array.from(new Set([
    ...models.filter((model) => model.installed).map((model) => model.model_name),
    ...archivedModels,
  ]));

  const toggle = (value: string, values: string[], update: (next: string[]) => void) => {
    update(values.includes(value) ? values.filter((item) => item !== value) : [...values, value]);
  };

  const canCreate = selectedModels.length >= 1
    && selectedPacked.length >= 2
    && selectedObfuscated.length >= 2
    && !saving;

  const createBatch = async () => {
    if (!canCreate) return;
    setSaving(true);
    setMessage(null);
    try {
      const response = await fetch("/api/acceptance/batches", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: batchName.trim() || `自定义验收批次 ${new Date().toLocaleString("zh-CN")}`,
          model_names: selectedModels,
          packed_task_ids: selectedPacked,
          obfuscated_task_ids: selectedObfuscated,
        }),
      });
      if (!response.ok) {
        let detail = `HTTP ${response.status}`;
        try {
          const body = await response.json();
          if (typeof body?.detail === "string") detail = body.detail;
        } catch {
          /* ignore */
        }
        throw new Error(detail);
      }
      const created: CustomAcceptanceBatch = await response.json();
      setBatches((current) => [created, ...current]);
      setBatchName("");
      setMessage({
        kind: "success",
        text: language === "zh"
          ? `已建立 ${created.batch_id}，完成度 ${created.completed_groups}/3。`
          : `Created ${created.batch_id}; completion ${created.completed_groups}/3.`,
      });
    } catch (error) {
      setMessage({
        kind: "error",
        text: error instanceof Error ? error.message : "创建批次失败",
      });
    } finally {
      setSaving(false);
    }
  };

  return (
    <section className="rounded-2xl bg-[#fdfaf3] border border-[#b9d6f3] shadow-sm overflow-hidden">
      <div className="p-5 border-b border-[#dfd6bf] bg-[#eef4fb]/50 flex flex-col lg:flex-row lg:items-center justify-between gap-3">
        <div>
          <h3 className="text-sm font-bold text-[#2b3638] flex items-center gap-2">
            <Link2 className="w-4 h-4 text-[#268bd2]" />
            {language === "zh" ? "自定义验收批次 · 后端关联" : "Custom acceptance batch · backend links"}
          </h3>
          <p className="text-[11px] text-[#586e75] mt-1 leading-relaxed">
            {language === "zh"
              ? "关联模型、已授权实验室任务、目标文件与审计报告；这里计算执行完成度，固定 Benchmark 的 P/R/F1 保持独立。"
              : "Links models, authorized lab tasks, target files and reports. This tracks execution completion; fixed Benchmark P/R/F1 stays separate."}
          </p>
        </div>
        <div className="flex gap-2">
          {onOpenTestLab && (
            <button type="button" onClick={onOpenTestLab} className="px-3 py-1.5 rounded-lg bg-[#fdfaf3] border border-[#dfd6bf] text-xs font-semibold text-[#586e75] flex items-center gap-1.5 cursor-pointer hover:bg-white">
              <FolderOpen className="w-3.5 h-3.5" />
              {language === "zh" ? "去实验室上传/分析" : "Upload/analyze in lab"}
            </button>
          )}
          <button type="button" onClick={() => void load()} disabled={loading} className="p-2 rounded-lg bg-[#fdfaf3] border border-[#dfd6bf] text-[#586e75] cursor-pointer disabled:opacity-50" title="刷新关联数据">
            <RotateCcw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
          </button>
        </div>
      </div>

      <div className="p-5 space-y-4">
        {message && (
          <div role="status" className={`rounded-lg border px-3 py-2 text-xs ${message.kind === "success" ? "bg-[#edf5d3] border-[#cce38d] text-[#657b00]" : "bg-[#fce8e6] border-[#f5b8b5] text-[#dc322f]"}`}>
            {message.text}
          </div>
        )}

        <input
          value={batchName}
          onChange={(event) => setBatchName(event.target.value)}
          className="w-full rounded-lg border border-[#dfd6bf] bg-white px-3 py-2 text-xs text-[#2b3638] outline-none focus:border-[#2aa198]"
          placeholder={language === "zh" ? "批次名称（可选，例如：答辩现场验收）" : "Batch name (optional)"}
          maxLength={160}
        />

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">
          <BatchSelector
            title={language === "zh" ? "A · 开源大模型（至少 1 个）" : "A · Local model (min 1)"}
            emptyText={language === "zh" ? "未探测到已安装或已归档模型。" : "No installed or archived model detected."}
            options={modelChoices.map((name) => ({
              id: name,
              label: name,
              hint: tasks.some((task) => modelName(task) === name && task.status === "completed")
                ? (language === "zh" ? "已有完成任务与报告" : "completed task/report available")
                : (language === "zh" ? "尚需在实验室运行并归档" : "run and archive in lab first"),
            }))}
            selected={selectedModels}
            onToggle={(id) => toggle(id, selectedModels, setSelectedModels)}
          />
          <BatchSelector
            title={language === "zh" ? "B · 加壳任务（至少 2 个）" : "B · Packed tasks (min 2)"}
            emptyText={language === "zh" ? "暂无加壳实验室任务。" : "No packed lab tasks."}
            options={packedTasks.map((task) => ({
              id: task.task_id,
              label: task.target.path.split(/[\\/]/).pop() || task.target.path,
              hint: `${task.status.toUpperCase()} · ${task.task_id.slice(-8)}`,
            }))}
            selected={selectedPacked}
            onToggle={(id) => toggle(id, selectedPacked, setSelectedPacked)}
          />
          <BatchSelector
            title={language === "zh" ? "C · 混淆任务（至少 2 个）" : "C · Obfuscated tasks (min 2)"}
            emptyText={language === "zh" ? "暂无混淆实验室任务。" : "No obfuscated lab tasks."}
            options={obfuscatedTasks.map((task) => ({
              id: task.task_id,
              label: task.target.path.split(/[\\/]/).pop() || task.target.path,
              hint: `${task.status.toUpperCase()} · ${task.task_id.slice(-8)}`,
            }))}
            selected={selectedObfuscated}
            onToggle={(id) => toggle(id, selectedObfuscated, setSelectedObfuscated)}
          />
        </div>

        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 rounded-xl bg-[#f8f2e3] border border-[#dfd6bf] p-3">
          <p className="text-[11px] text-[#586e75]">
            {language === "zh"
              ? `当前选择：模型 ${selectedModels.length}；加壳 ${selectedPacked.length}/2；混淆 ${selectedObfuscated.length}/2。`
              : `Selected: models ${selectedModels.length}; packed ${selectedPacked.length}/2; obfuscated ${selectedObfuscated.length}/2.`}
          </p>
          <button type="button" onClick={() => void createBatch()} disabled={!canCreate} className="px-4 py-2 rounded-lg bg-[#2aa198] text-white text-xs font-bold flex items-center justify-center gap-1.5 cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed">
            <Play className="w-3 h-3 fill-current" />
            {saving ? (language === "zh" ? "正在建立关联..." : "Linking...") : (language === "zh" ? "创建并核验批次" : "Create and verify batch")}
          </button>
        </div>

        {batches.length > 0 && (
          <div className="space-y-2">
            <h4 className="text-xs font-bold text-[#2b3638]">
              {language === "zh" ? "已保存验收批次" : "Saved acceptance batches"}
            </h4>
            {batches.map((batch) => (
              <details key={batch.batch_id} className="rounded-xl border border-[#dfd6bf] bg-[#fcf8ed] p-3">
                <summary className="cursor-pointer list-none flex flex-col md:flex-row md:items-center justify-between gap-2">
                  <div>
                    <div className="text-xs font-bold text-[#2b3638]">{batch.name}</div>
                    <div className="text-[10px] font-mono text-[#839496] mt-0.5">{batch.batch_id}</div>
                  </div>
                  <span className={`px-2 py-1 rounded border text-[10px] font-mono font-bold ${batch.state === "completed" ? "bg-[#edf5d3] border-[#cce38d] text-[#657b00]" : "bg-[#fbf4e6] border-[#ecd8a6] text-[#b58900]"}`}>
                    EXECUTION {batch.completed_groups}/{batch.total_groups} · {batch.state.toUpperCase()}
                  </span>
                </summary>
                <div className="mt-3 grid grid-cols-1 md:grid-cols-3 gap-2">
                  {batch.groups.map((group) => (
                    <div key={group.group_id} className="rounded-lg bg-white border border-[#dfd6bf] p-2.5 text-xs">
                      <div className="flex items-center justify-between gap-2">
                        <strong className="text-[#2b3638]">{group.group_id.toUpperCase()} · {group.title}</strong>
                        <span className={group.execution_complete ? "text-[#859900]" : "text-[#b58900]"}>{group.execution_complete ? "✓" : "…"}</span>
                      </div>
                      <p className="text-[10px] text-[#586e75] mt-1">{group.summary}</p>
                    </div>
                  ))}
                </div>
                <div className="mt-3 space-y-1.5">
                  {batch.task_links.map((item) => (
                    <div key={`${item.group_id}-${item.task_id}`} className="rounded-lg bg-[#f5eed9] border border-[#dfd6bf] px-3 py-2.5 text-[10px]">
                      <div className="flex flex-col md:flex-row md:items-center justify-between gap-1">
                        <div className="min-w-0">
                          <span className="font-mono font-bold text-[#2aa198] mr-2">{item.group_id.toUpperCase()}</span>
                          <span className="text-[#2b3638]">{item.model_name || item.file_name}</span>
                          <span className="font-mono text-[#839496] ml-2">{item.task_id}</span>
                        </div>
                        {item.report_available ? (
                          <a href={item.report_links.html} target="_blank" rel="noreferrer" className="text-[#268bd2] font-semibold hover:underline">HTML REPORT ↗</a>
                        ) : (
                          <span className="text-[#b58900]">REPORT PENDING</span>
                        )}
                      </div>
                      {(item.declared_protection || item.observed_protection_methods?.length > 0) && (
                        <div className="mt-2 flex flex-col gap-1.5 border-t border-[#dfd6bf] pt-2 sm:flex-row sm:items-center sm:flex-wrap">
                          <span className="font-mono font-bold text-[#b58900]">
                            {language === "zh" ? "样本声明" : "Declared"} · {item.declared_protection || (language === "zh" ? "未声明" : "None")}
                          </span>
                          <span className="hidden text-[#b7ad92] sm:inline">→</span>
                          <div className="flex flex-wrap gap-1">
                            {item.observed_protection_methods?.length ? item.observed_protection_methods.map((method) => (
                              <span key={method} className="rounded-full border border-[#bfe3e0] bg-[#eef7f6] px-2 py-0.5 text-[#147f79]">
                                {language === "zh" ? "观察" : "Observed"} · {protectionMethodLabel(method, language)}
                              </span>
                            )) : <span className="text-[#839496]">{language === "zh" ? "尚无可归因静态信号" : "No attributable signal"}</span>}
                          </div>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
                <p className="mt-3 text-[10px] text-[#839496]">{batch.metric_note}</p>
              </details>
            ))}
          </div>
        )}
      </div>
    </section>
  );
};

const BatchSelector: React.FC<{
  title: string;
  emptyText: string;
  options: Array<{ id: string; label: string; hint: string }>;
  selected: string[];
  onToggle: (id: string) => void;
}> = ({ title, emptyText, options, selected, onToggle }) => (
  <div className="rounded-xl bg-[#f8f2e3] border border-[#dfd6bf] p-3 min-h-36">
    <h4 className="text-xs font-bold text-[#2b3638] mb-2">{title}</h4>
    <div className="space-y-1.5 max-h-44 overflow-y-auto pr-1">
      {options.length ? options.map((option) => (
        <label key={option.id} className="flex items-start gap-2 rounded-lg bg-white border border-[#dfd6bf] px-2.5 py-2 cursor-pointer hover:border-[#2aa198]">
          <input type="checkbox" checked={selected.includes(option.id)} onChange={() => onToggle(option.id)} className="mt-0.5 accent-[#2aa198]" />
          <span className="min-w-0">
            <span className="text-[11px] font-semibold text-[#2b3638] block truncate">{option.label}</span>
            <span className="text-[9px] font-mono text-[#839496] block truncate">{option.hint}</span>
          </span>
        </label>
      )) : <p className="text-[10px] text-[#839496] leading-relaxed">{emptyText}</p>}
    </div>
  </div>
);

function formatTime(iso: string, language: string): string {
  try {
    const date = new Date(iso);
    return date.toLocaleString(language === "zh" ? "zh-CN" : "en-US", {
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
    });
  } catch {
    return iso;
  }
}

const MetaCard: React.FC<{ icon: any; label: string; value: string }> = ({ icon: Icon, label, value }) => (
  <div className="p-4 rounded-xl bg-[#fdfaf3] border border-[#dfd6bf] shadow-2xs flex items-center gap-3">
    <div className="w-9 h-9 rounded-lg bg-[#2aa198]/10 border border-[#2aa198]/30 flex items-center justify-center text-[#2aa198] shrink-0">
      <Icon className="w-4 h-4" />
    </div>
    <div className="min-w-0">
      <div className="text-[10px] text-[#839496] font-medium truncate">{label}</div>
      <div className="text-sm font-mono font-bold text-[#2b3638] truncate">{value}</div>
    </div>
  </div>
);

const LLMUsageOverview: React.FC<{
  group: AcceptanceGroup | null;
  summary: LLMComparisonSummary;
}> = ({ group, summary }) => {
  const { t, language } = useTranslation();
  const rows = summary.metrics;
  const sourceLabel = summary.source === "canonical_artifact"
    ? (language === "zh" ? "当前规范产物" : "Current artifact")
    : summary.source === "published_baseline"
      ? (language === "zh" ? "已发布真实基线" : "Published real baseline")
      : (language === "zh" ? "暂无产物" : "Unavailable");
  return (
    <section className="rounded-2xl bg-[#fdfaf3] border border-[#dfd6bf] shadow-sm overflow-hidden">
      <div className="p-5 border-b border-[#dfd6bf] flex flex-col lg:flex-row lg:items-center justify-between gap-3">
        <div>
          <h3 className="text-sm font-bold text-[#2b3638] flex items-center gap-2">
            <Gauge className="w-4 h-4 text-[#2aa198]" />
            {language === "zh" ? "LLM 指标、Token 与费用看板" : "LLM Metrics, Tokens & Cost"}
          </h3>
          <p className="text-[11px] text-[#839496] mt-1">
            {language === "zh"
              ? "真实 Provider usage、版本化费率估算、分类指标与 Evidence Coverage 集中展示。"
              : "Real provider usage, versioned cost estimates, classification metrics and evidence coverage in one view."}
          </p>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <span className="px-2.5 py-1 rounded-lg border border-[#b9d6f3] bg-[#eef4fb] text-[10px] font-mono font-bold text-[#268bd2] uppercase">
            {sourceLabel}{summary.manifest_matches === true ? " · MANIFEST MATCH" : ""}
          </span>
          {(group?.providers ?? []).map((provider) => (
            <span
              key={provider.provider}
              className={`px-2.5 py-1 rounded-lg border text-[10px] font-mono font-bold uppercase ${
                provider.configured
                  ? "bg-[#edf5d3] text-[#657b00] border-[#cce38d]"
                  : "bg-[#eee8d5] text-[#839496] border-[#dfd6bf]"
              }`}
            >
              {provider.provider} · {provider.configured ? (language === "zh" ? "已配置" : "ready") : (language === "zh" ? "未配置" : "not set")}
            </span>
          ))}
        </div>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-[11px] font-mono border-collapse min-w-[820px]">
          <thead>
            <tr className="text-left text-[#839496] bg-[#f8f2e3] border-b border-[#dfd6bf]">
              <th className="py-2.5 px-5 font-medium">{t("accColMethod")}</th>
              <th className="py-2.5 px-2 font-medium text-right">{t("accColSamples")}</th>
              <th className="py-2.5 px-2 font-medium text-right">P / R / F1</th>
              <th className="py-2.5 px-2 font-medium text-right">{t("accColTokens")}</th>
              <th className="py-2.5 px-2 font-medium text-right">{t("accColCost")}</th>
              <th className="py-2.5 px-5 font-medium text-right">{t("accColEvidence")}</th>
            </tr>
          </thead>
          <tbody>
            {rows.length > 0 ? rows.map((row) => (
              <tr key={row.method} className="border-b last:border-b-0 border-[#eee8d5] text-[#2b3638]">
                <td className="py-2.5 px-5 font-bold text-[#2aa198] whitespace-nowrap">{row.method}</td>
                <td className="py-2.5 px-2 text-right">{row.samples}</td>
                <td className="py-2.5 px-2 text-right">{row.precision.toFixed(3)} / {row.recall.toFixed(3)} / {row.f1.toFixed(3)}</td>
                <td className="py-2.5 px-2 text-right">{row.total_tokens != null ? row.total_tokens.toLocaleString() : "—"}</td>
                <td className="py-2.5 px-2 text-right whitespace-nowrap">
                  {row.total_token_cost != null
                    ? `${row.total_token_cost.toFixed(6)} ${row.token_cost_currency || ""}`.trim()
                    : "—"}
                </td>
                <td className="py-2.5 px-5 text-right">{row.evidence_chain_coverage.toFixed(3)}</td>
              </tr>
            )) : (
              <tr>
                <td colSpan={6} className="px-5 py-6 text-center text-[#839496]">
                  {language === "zh"
                    ? "当前工作区未检测到 llm-comparison 规范指标产物；生成或恢复产物后会自动显示，不以 0 冒充缺失 usage。"
                    : "No canonical llm-comparison artifact is available in this workspace. Metrics appear automatically when restored or generated; missing usage is never shown as zero."}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      <div className="px-5 py-2.5 border-t border-[#dfd6bf] bg-[#fcf8ed] text-[10px] text-[#839496]">
        {summary.source === "published_baseline" && (
          <span className="text-[#b58900] mr-2">
            {language === "zh"
              ? "当前运行产物缺失，显示已发布的 2026-09-11 真实聚合基线；本次验收状态仍按当前产物计算。"
              : "The current run artifact is absent, so this shows the published 2026-09-11 real aggregate baseline; acceptance status still uses current artifacts only."}
          </span>
        )}
        {t("accComparisonNote")}
      </div>
    </section>
  );
};

const GroupCard: React.FC<{
  group: AcceptanceGroup;
  running: boolean;
  onOpen: () => void;
  onRun: () => void;
}> = ({ group, running, onOpen, onRun }) => {
  const { t, language } = useTranslation();
  const Icon = GROUP_ICON[group.group_id] || Shield;
  return (
    <div className="rounded-2xl bg-[#fdfaf3] border border-[#dfd6bf] shadow-sm overflow-hidden flex flex-col">
      <div className={`h-1 bg-gradient-to-r ${GROUP_ACCENT[group.group_id] || GROUP_ACCENT.a}`} />
      <div className="p-5 flex-1 flex flex-col">
        <div className="flex items-start justify-between gap-2 mb-2">
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-lg bg-[#eee8d5] border border-[#dfd6bf] flex items-center justify-center text-[#2aa198]">
              <Icon className="w-4 h-4" />
            </div>
            <h4 className="text-sm font-bold text-[#2b3638] leading-tight">{group.title}</h4>
          </div>
          <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase border shrink-0 ${STATUS_STYLES[group.status]}`}>
            {t(`accStatus_${group.status}`)}
          </span>
        </div>

        <p className="text-xs text-[#586e75] leading-relaxed flex-1">{group.summary}</p>

        {/* Compact facts */}
        <div className="mt-4 space-y-1.5">
          {group.providers.length > 0 && (
            <FactRow label={t("accProvidersTitle")} value={`${group.providers.filter((p) => p.configured).length}/${group.providers.length} ${t("accConfigured")}`} />
          )}
          {group.targets.length > 0 && (
            <FactRow label={t("accTwoTargets")} value={String(group.targets.length)} />
          )}
          <FactRow
            label="Conditions"
            value={`${group.conditions.filter((c) => c.met).length}/${group.conditions.length}`}
          />
        </div>

        <div className="mt-4 pt-3 border-t border-[#dfd6bf] flex items-center gap-2">
          <button
            onClick={onOpen}
            className="flex-1 px-3 py-1.5 rounded-lg bg-[#eee8d5] hover:bg-[#e6deca] border border-[#dfd6bf] text-xs font-semibold text-[#2b3638] transition-colors cursor-pointer"
          >
            {language === "zh" ? "查看明细" : "Details"}
          </button>
          <button
            onClick={onRun}
            disabled={running}
            className="px-3 py-1.5 rounded-lg bg-[#2aa198] hover:bg-[#238b83] text-white text-xs font-bold flex items-center gap-1.5 transition-colors cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <Play className={`w-3 h-3 fill-current ${running ? "animate-spin" : ""}`} />
            {running ? t("accRunning") : t("accRunGroup")}
          </button>
        </div>
      </div>
    </div>
  );
};

const FactRow: React.FC<{ label: string; value: string }> = ({ label, value }) => (
  <div className="flex items-center justify-between text-[11px]">
    <span className="text-[#839496]">{label}</span>
    <span className="font-mono font-semibold text-[#2b3638]">{value}</span>
  </div>
);

const GroupDetail: React.FC<{
  group: AcceptanceGroup;
  running: boolean;
  onRun: (providers?: string[]) => void;
  onBack: () => void;
}> = ({ group, running, onRun, onBack }) => {
  const { t, language } = useTranslation();
  const Icon = GROUP_ICON[group.group_id] || Shield;
  const configuredProviders = group.providers.filter((p) => p.configured).map((p) => p.provider);
  const [selectedProviders, setSelectedProviders] = useState<string[]>(configuredProviders);

  const toggleProvider = (provider: string) => {
    setSelectedProviders((current) =>
      current.includes(provider)
        ? current.filter((item) => item !== provider)
        : [...current, provider]
    );
  };

  const handleRun = () => {
    if (group.group_id === "a") {
      onRun(selectedProviders);
    } else {
      onRun();
    }
  };

  return (
    <div className="space-y-5">
      {/* Detail header */}
      <div className="p-5 rounded-2xl bg-[#f4eedb] border border-[#dfd6bf] shadow-sm">
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-center gap-2">
            <button
              onClick={onBack}
              className="p-1.5 rounded-lg bg-[#fdfaf3] hover:bg-[#ffffff] border border-[#dfd6bf] text-[#586e75] hover:text-[#2b3638] transition-colors cursor-pointer"
              title={t("accBack")}
            >
              <ArrowLeft className="w-4 h-4" />
            </button>
            <div className="w-8 h-8 rounded-lg bg-[#eee8d5] border border-[#dfd6bf] flex items-center justify-center text-[#2aa198]">
              <Icon className="w-4 h-4" />
            </div>
            <h3 className="text-base font-bold text-[#2b3638]">{group.title}</h3>
            <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase border ${STATUS_STYLES[group.status]}`}>
              {t(`accStatus_${group.status}`)}
            </span>
          </div>
          <button
            onClick={handleRun}
            disabled={running || (group.group_id === "a" && selectedProviders.length < 1)}
            className="px-3.5 py-1.5 rounded-xl bg-[#2aa198] hover:bg-[#238b83] text-white text-xs font-bold flex items-center gap-1.5 transition-colors cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed shrink-0"
          >
            <Play className={`w-3 h-3 fill-current ${running ? "animate-spin" : ""}`} />
            {running ? t("accRunning") : t("accRunGroup")}
          </button>
        </div>
        <p className="text-xs text-[#586e75] mt-3 leading-relaxed">{group.summary}</p>
      </div>

      {/* Conditions */}
      <div className="p-5 rounded-2xl bg-[#fdfaf3] border border-[#dfd6bf] shadow-sm">
        <h4 className="text-xs font-bold text-[#2b3638] mb-3 flex items-center gap-1.5">
          <ClipboardCheck className="w-3.5 h-3.5 text-[#2aa198]" />
          {t("accConditionsTitle")}
        </h4>
        <div className="space-y-2">
          {group.conditions.map((condition) => (
            <div
              key={condition.key}
              className={`flex items-start gap-2.5 p-3 rounded-xl border ${
                condition.met ? "bg-[#f4f8ec] border-[#dbe6b8]" : "bg-[#fcf8ed] border-[#e6dcc3]"
              }`}
            >
              {condition.met ? (
                <CheckCircle2 className="w-4 h-4 text-[#859900] shrink-0 mt-0.5" />
              ) : (
                <XCircle className="w-4 h-4 text-[#cb4b16] shrink-0 mt-0.5" />
              )}
              <div className="min-w-0">
                <div className="text-xs font-semibold text-[#2b3638]">{condition.label}</div>
                <div className="text-[11px] text-[#586e75] mt-0.5">{condition.detail}</div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Providers (Group A) */}
      {group.providers.length > 0 && (
        <div className="p-5 rounded-2xl bg-[#fdfaf3] border border-[#dfd6bf] shadow-sm">
          <h4 className="text-xs font-bold text-[#2b3638] mb-1 flex items-center gap-1.5">
            <Cpu className="w-3.5 h-3.5 text-[#268bd2]" />
            {t("accProvidersTitle")}
          </h4>
          <p className="text-[11px] text-[#586e75] mb-3">{t("accSelectProvidersHint")}</p>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            {group.providers.map((provider) => {
              const selected = selectedProviders.includes(provider.provider);
              return (
                <div
                  key={provider.provider}
                  className={`p-3 rounded-xl border ${
                    provider.configured ? "bg-[#f4f8ec] border-[#dbe6b8]" : "bg-[#fcf8ed] border-[#e6dcc3] opacity-60"
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <label className="flex items-center gap-2 cursor-pointer select-none">
                      <input
                        type="checkbox"
                        checked={selected}
                        disabled={!provider.configured}
                        onChange={() => toggleProvider(provider.provider)}
                        className="accent-[#2aa198] w-3.5 h-3.5 cursor-pointer disabled:cursor-not-allowed"
                      />
                      <span className="font-mono font-bold text-xs text-[#2b3638]">{provider.provider}</span>
                    </label>
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${
                        provider.configured
                          ? "bg-[#edf5d3] text-[#859900] border-[#cce38d]"
                          : "bg-[#eee8d5] text-[#586e75] border-[#dfd6bf]"
                      }`}
                    >
                      {provider.configured ? t("accConfigured") : t("accNotConfigured")}
                    </span>
                  </div>
                  {provider.model && (
                    <div className="text-[11px] font-mono text-[#586e75] mt-1.5 truncate">model: {provider.model}</div>
                  )}
                  {provider.default_for_planner && (
                    <div className="text-[10px] text-[#2aa198] font-semibold mt-1 flex items-center gap-1">
                      <Lock className="w-3 h-3" />
                      {t("accDefaultPlanner")}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
          <div className="text-[11px] text-[#839496] mt-2 font-mono">
            {t("accSelectedCount")}: {selectedProviders.length}
          </div>
        </div>
      )}

      {/* Dual-model comparison (Group A) */}
      {group.comparison.length > 0 && (
        <div className="p-5 rounded-2xl bg-[#fdfaf3] border border-[#dfd6bf] shadow-sm overflow-x-auto">
          <h4 className="text-xs font-bold text-[#2b3638] mb-3 flex items-center gap-1.5">
            <Gauge className="w-3.5 h-3.5 text-[#2aa198]" />
            {t("accComparisonTitle")}
          </h4>
          <table className="w-full text-[11px] font-mono border-collapse min-w-[720px]">
            <thead>
              <tr className="text-left text-[#839496] border-b border-[#dfd6bf]">
                <th className="py-2 pr-3 font-medium">{t("accColMethod")}</th>
                <th className="py-2 px-2 font-medium text-right">{t("accColSamples")}</th>
                <th className="py-2 px-2 font-medium text-right">TP/FP/TN/FN</th>
                <th className="py-2 px-2 font-medium text-right">P / R / F1</th>
                <th className="py-2 px-2 font-medium text-right">{t("accColTokens")}</th>
                <th className="py-2 px-2 font-medium text-right">{t("accColCost")}</th>
                <th className="py-2 px-2 font-medium text-right">{t("accColEvidence")}</th>
              </tr>
            </thead>
            <tbody>
              {group.comparison.map((row) => (
                <tr key={row.method} className="border-b border-[#eee8d5] text-[#2b3638]">
                  <td className="py-1.5 pr-3 font-bold text-[#2aa198] whitespace-nowrap">{row.method}</td>
                  <td className="py-1.5 px-2 text-right">{row.samples}</td>
                  <td className="py-1.5 px-2 text-right">
                    {row.true_positive}/{row.false_positive}/{row.true_negative}/{row.false_negative}
                  </td>
                  <td className="py-1.5 px-2 text-right">
                    {row.precision.toFixed(3)} / {row.recall.toFixed(3)} / {row.f1.toFixed(3)}
                  </td>
                  <td className="py-1.5 px-2 text-right">
                    {row.total_tokens != null ? row.total_tokens.toLocaleString() : "—"}
                  </td>
                  <td className="py-1.5 px-2 text-right whitespace-nowrap">
                    {row.total_token_cost != null
                      ? `${row.total_token_cost.toFixed(6)} ${row.token_cost_currency || ""}`.trim()
                      : "—"}
                  </td>
                  <td className="py-1.5 px-2 text-right">{row.evidence_chain_coverage.toFixed(3)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="text-[10px] text-[#839496] mt-2">{t("accComparisonNote")}</p>
        </div>
      )}

      {/* Targets (Group B/C) */}
      {group.targets.length > 0 && (
        <div className="p-5 rounded-2xl bg-[#fdfaf3] border border-[#dfd6bf] shadow-sm">
          <h4 className="text-xs font-bold text-[#2b3638] mb-3 flex items-center gap-1.5">
            <FileSearch className="w-3.5 h-3.5 text-[#6c71c4]" />
            {t("accTargetsTitle")}
          </h4>
          <div className="space-y-3">
            {group.targets.map((target) => (
              <div key={target.sample_id} className="p-4 rounded-xl border border-[#dfd6bf] bg-[#fcf8ed]">
                <div className="flex items-start justify-between gap-2 flex-wrap">
                  <div>
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-mono font-bold text-xs text-[#2b3638]">{target.sample_id}</span>
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-[#eee8d5] text-[#2aa198] border border-[#dfd6bf] uppercase">
                        {target.protection_kind}
                      </span>
                      {target.protector_product && (
                        <span className="text-[11px] text-[#586e75]">{target.protector_product}</span>
                      )}
                    </div>
                    <div className="text-xs text-[#586e75] mt-1">
                      {target.software_name}
                      {target.author ? ` · ${target.author}` : ""}
                      {target.version ? ` v${target.version}` : ""}
                    </div>
                  </div>
                  <div className="flex items-center gap-1.5 flex-wrap">
                    <IntakeBadge label={language === "zh" ? "文件落地" : "Material"} ok={target.material_present} />
                    <IntakeBadge label="SHA-256" ok={target.sha256_verified} />
                    <IntakeBadge label={language === "zh" ? "准入就绪" : "Intake Ready"} ok={target.intake_ready} />
                  </div>
                </div>

                {(target.protector_product || target.protector_secondary) && (
                  <div className="mt-3 rounded-xl border border-[#e3d5ae] bg-[#fbf4e6] p-3">
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-[10px] font-mono font-bold uppercase text-[#b58900]">
                        {language === "zh" ? "样本声明的保护/混淆方法" : "Declared protection method"}
                      </span>
                      <span className="rounded border border-[#e3d5ae] bg-white px-2 py-0.5 text-[9px] font-mono text-[#8a7000]">DECLARED ≠ VERDICT</span>
                    </div>
                    <div className="mt-2 flex flex-wrap gap-1.5">
                      {target.protector_product && (
                        <span className="rounded-full border border-[#e3d5ae] bg-white px-2.5 py-1 text-[10px] font-bold text-[#6f5b00]">
                          PRIMARY · {target.protector_product}
                        </span>
                      )}
                      {target.protector_secondary && (
                        <span className="rounded-full border border-[#d8d3ec] bg-[#f4f1f9] px-2.5 py-1 text-[10px] font-semibold text-[#6c71c4]">
                          SECONDARY · {target.protector_secondary}
                        </span>
                      )}
                      {target.static_signals_observed != null && (
                        <span className={`rounded-full border px-2.5 py-1 text-[10px] font-semibold ${target.static_signals_observed ? "border-[#bfe3e0] bg-[#eef7f6] text-[#147f79]" : "border-[#dfd6bf] bg-[#eee8d5] text-[#839496]"}`}>
                          {target.static_signals_observed ? (language === "zh" ? "✓ 已观察静态信号" : "✓ Static signal observed") : (language === "zh" ? "尚未观察静态信号" : "No static signal observed")}
                        </span>
                      )}
                    </div>
                  </div>
                )}

                {target.finding_status_counts && Object.keys(target.finding_status_counts).length > 0 && (
                  <div className="flex items-center gap-2 mt-2.5 flex-wrap">
                    {Object.entries(target.finding_status_counts).map(([status, count]) => (
                      <span key={status} className="px-2 py-0.5 rounded text-[10px] font-mono bg-[#eee8d5] text-[#586e75] border border-[#dfd6bf]">
                        {status}: {count}
                      </span>
                    ))}
                  </div>
                )}

                {target.issues.length > 0 && (
                  <div className="mt-2.5 space-y-1">
                    {target.issues.map((issue, index) => (
                      <p key={index} className="text-[11px] text-[#cb4b16] flex gap-1.5">
                        <AlertTriangle className="w-3 h-3 shrink-0 mt-0.5" />
                        <span>{issue}</span>
                      </p>
                    ))}
                  </div>
                )}

                {Object.keys(target.report_links).length > 0 && (
                  <div className="flex items-center gap-2 mt-2.5 flex-wrap">
                    <span className="text-[10px] text-[#839496]">{t("accReportLinks")}:</span>
                    {Object.entries(target.report_links).map(([format, uri]) => (
                      <a
                        key={format}
                        href={uri}
                        target="_blank"
                        rel="noreferrer"
                        className="text-[10px] font-mono text-[#268bd2] hover:underline flex items-center gap-1"
                      >
                        {format.toUpperCase()} <ExternalLink className="w-2.5 h-2.5" />
                      </a>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Latest run */}
      {Object.keys(group.latest_run).length > 0 && (
        <div className="p-4 rounded-xl bg-[#eee8d5] border border-[#dfd6bf]">
          <div className="text-[10px] text-[#839496] font-medium mb-1.5">latest_run</div>
          <pre className="text-[11px] font-mono text-[#586e75] whitespace-pre-wrap break-all">
            {JSON.stringify(group.latest_run, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
};

const IntakeBadge: React.FC<{ label: string; ok: boolean }> = ({ label, ok }) => (
  <span
    className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${
      ok ? "bg-[#edf5d3] text-[#859900] border-[#cce38d]" : "bg-[#fce8e6] text-[#dc322f] border-[#f5b8b5]"
    }`}
  >
    {ok ? "✓" : "✗"} {label}
  </span>
);
