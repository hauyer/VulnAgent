import React, { useCallback, useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  Check,
  CheckCircle2,
  Code2,
  Copy,
  Download,
  FileCheck2,
  Lock,
  RefreshCw,
  ShieldCheck,
  Sparkles,
} from "lucide-react";
import { ControlledPocBundle, Task, VulnerabilityCandidate } from "../types.js";
import { useTranslation } from "../i18n.js";


interface ControlledPocViewProps {
  task: Task;
  findings: VulnerabilityCandidate[];
}


export const ControlledPocView: React.FC<ControlledPocViewProps> = ({ task, findings }) => {
  const { language } = useTranslation();
  const zh = language === "zh";
  const [bundles, setBundles] = useState<ControlledPocBundle[]>([]);
  const [selectedBundleId, setSelectedBundleId] = useState<string | null>(null);
  const [acknowledged, setAcknowledged] = useState(false);
  const [generatingId, setGeneratingId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [copied, setCopied] = useState(false);
  const [notice, setNotice] = useState<{ kind: "success" | "error"; text: string } | null>(null);

  const confirmed = findings.filter((item) => item.status === "confirmed");
  const selectedBundle = useMemo(
    () => bundles.find((item) => item.bundle_id === selectedBundleId) || bundles[0] || null,
    [bundles, selectedBundleId],
  );

  const loadBundles = useCallback(async () => {
    setLoading(true);
    try {
      const response = await fetch(`/api/tasks/${task.task_id}/poc`);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const data: ControlledPocBundle[] = await response.json();
      setBundles(data);
      setSelectedBundleId((current) => current && data.some((item) => item.bundle_id === current) ? current : data[0]?.bundle_id || null);
    } catch (error) {
      setNotice({ kind: "error", text: error instanceof Error ? error.message : "PoC data load failed" });
    } finally {
      setLoading(false);
    }
  }, [task.task_id]);

  useEffect(() => {
    setAcknowledged(false);
    setNotice(null);
    void loadBundles();
  }, [loadBundles]);

  const generate = async (vulnerabilityId: string) => {
    if (!acknowledged || generatingId) return;
    setGeneratingId(vulnerabilityId);
    setNotice(null);
    try {
      const response = await fetch(`/api/tasks/${task.task_id}/poc`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          vulnerability_id: vulnerabilityId,
          acknowledge_controlled_scope: true,
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
      const bundle: ControlledPocBundle = await response.json();
      setBundles((current) => [bundle, ...current.filter((item) => item.bundle_id !== bundle.bundle_id)]);
      setSelectedBundleId(bundle.bundle_id);
      setNotice({
        kind: "success",
        text: zh ? "受控 PoC 复现代码已生成并写入审计记录。" : "Controlled PoC replay code generated and audited.",
      });
    } catch (error) {
      setNotice({ kind: "error", text: error instanceof Error ? error.message : "PoC generation failed" });
    } finally {
      setGeneratingId(null);
    }
  };

  const copyCode = async () => {
    if (!selectedBundle) return;
    await navigator.clipboard.writeText(selectedBundle.code);
    setCopied(true);
    setTimeout(() => setCopied(false), 1600);
  };

  return (
    <div className="space-y-6">
      <section className="p-5 rounded-2xl bg-[#f4eedb] border border-[#dfd6bf] shadow-sm flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1 flex-wrap">
            <div className="w-7 h-7 rounded-lg bg-[#6c71c4]/10 border border-[#6c71c4]/30 flex items-center justify-center text-[#6c71c4]">
              <Code2 className="w-4 h-4" />
            </div>
            <h2 className="text-base font-bold text-[#2b3638]">
              {zh ? "受控 PoC 复现与验证代码" : "Controlled PoC Evidence Replay"}
            </h2>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#edf5d3] text-[#657b00] border border-[#cce38d] font-bold">
              CONFIRMED ONLY
            </span>
          </div>
          <p className="text-xs text-[#586e75] leading-relaxed max-w-3xl">
            {zh
              ? "仅为已经独立确认的本地漏洞生成只读证据复现脚本；验证目标哈希、源码证据行或 PE/ELF 文件头，不启动目标、不联网、不执行命令。"
              : "Generates read-only evidence replay for independently confirmed local findings. It verifies artifact hashes and evidence locations without running the target, networking, or commands."}
          </p>
        </div>
        <button type="button" onClick={() => void loadBundles()} disabled={loading} className="px-3 py-2 rounded-lg bg-[#fdfaf3] border border-[#dfd6bf] text-xs font-semibold text-[#586e75] flex items-center gap-1.5 cursor-pointer disabled:opacity-50">
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
          {zh ? "刷新产物" : "Refresh"}
        </button>
      </section>

      <section className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {[
          [Lock, zh ? "本地限定" : "Local only", "ON"],
          [ShieldCheck, zh ? "目标执行" : "Target execution", "OFF"],
          [FileCheck2, zh ? "网络访问" : "Network", "OFF"],
          [CheckCircle2, zh ? "确认门禁" : "Verdict gate", "CONFIRMED"],
        ].map(([Icon, label, value]) => {
          const GuardIcon = Icon as typeof Lock;
          return (
            <div key={String(label)} className="p-3.5 rounded-xl bg-[#fdfaf3] border border-[#dfd6bf] flex items-center gap-2.5">
              <GuardIcon className="w-4 h-4 text-[#2aa198]" />
              <div><div className="text-[10px] text-[#839496]">{String(label)}</div><div className="text-xs font-mono font-bold text-[#2b3638]">{String(value)}</div></div>
            </div>
          );
        })}
      </section>

      {notice && (
        <div role="status" className={`px-4 py-3 rounded-xl border text-xs flex items-center gap-2 ${notice.kind === "success" ? "bg-[#edf5d3] border-[#cce38d] text-[#657b00]" : "bg-[#fce8e6] border-[#f5b8b5] text-[#dc322f]"}`}>
          {notice.kind === "success" ? <CheckCircle2 className="w-4 h-4" /> : <AlertTriangle className="w-4 h-4" />}
          {notice.text}
        </div>
      )}

      <label className="flex items-start gap-3 p-4 rounded-xl bg-[#fff7df] border border-[#ecd8a6] cursor-pointer">
        <input type="checkbox" checked={acknowledged} onChange={(event) => setAcknowledged(event.target.checked)} className="mt-0.5 accent-[#b58900]" />
        <span>
          <strong className="text-xs text-[#2b3638] block">{zh ? "我确认仅生成本地、非武器化的验证型 PoC" : "I acknowledge the local, non-weaponized PoC boundary"}</strong>
          <small className="text-[10px] text-[#586e75] leading-relaxed block mt-1">
            {zh ? "该代码不会利用漏洞取得控制权；它只复核同一文件与已确认 Evidence 的一致性。" : "The code does not gain control through a vulnerability; it only replays verified evidence against the same artifact."}
          </small>
        </span>
      </label>

      <div className="grid grid-cols-1 xl:grid-cols-5 gap-5">
        <section className="xl:col-span-2 rounded-2xl bg-[#fdfaf3] border border-[#dfd6bf] shadow-sm overflow-hidden">
          <div className="p-4 border-b border-[#dfd6bf] bg-[#f8f2e3]">
            <h3 className="text-sm font-bold text-[#2b3638]">{zh ? "已确认漏洞门禁" : "Confirmed finding gate"}</h3>
            <p className="text-[10px] text-[#839496] mt-1">{confirmed.length} CONFIRMED · Task {task.task_id.slice(-10)}</p>
          </div>
          <div className="p-3 space-y-2 max-h-[620px] overflow-y-auto">
            {confirmed.length ? confirmed.map((finding) => {
              const existing = bundles.filter((item) => item.vulnerability_id === finding.vulnerability_id).length;
              return (
                <article key={finding.vulnerability_id} className="rounded-xl border border-[#dfd6bf] bg-[#fcf8ed] p-3 space-y-2">
                  <div className="flex items-start justify-between gap-2">
                    <div>
                      <div className="text-xs font-bold text-[#2b3638]">{finding.title}</div>
                      <div className="text-[10px] font-mono text-[#839496] mt-0.5">{finding.cwe_id || finding.vulnerability_type}</div>
                    </div>
                    <span className="px-2 py-0.5 rounded bg-[#edf5d3] border border-[#cce38d] text-[#657b00] text-[9px] font-mono font-bold">CONFIRMED</span>
                  </div>
                  <p className="text-[10px] text-[#586e75] line-clamp-2">{finding.description}</p>
                  <button type="button" onClick={() => void generate(finding.vulnerability_id)} disabled={!acknowledged || !!generatingId} className="w-full px-3 py-2 rounded-lg bg-[#6c71c4] hover:bg-[#5b60ac] text-white text-xs font-bold flex items-center justify-center gap-1.5 cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed">
                    <Sparkles className={`w-3.5 h-3.5 ${generatingId === finding.vulnerability_id ? "animate-spin" : ""}`} />
                    {generatingId === finding.vulnerability_id
                      ? (zh ? "生成并校验中..." : "Generating...")
                      : existing
                        ? (zh ? `重新生成验证代码（已有 ${existing}）` : `Regenerate (${existing})`)
                        : (zh ? "自动生成受控 PoC" : "Generate controlled PoC")}
                  </button>
                </article>
              );
            }) : (
              <div className="py-12 text-center text-xs text-[#839496]">
                <ShieldCheck className="w-8 h-8 mx-auto mb-2 opacity-50" />
                {zh ? "当前任务没有可生成 PoC 的已确认漏洞。" : "No confirmed finding is eligible for PoC generation."}
              </div>
            )}
          </div>
        </section>

        <section className="xl:col-span-3 rounded-2xl bg-[#172033] border border-[#26354d] shadow-sm overflow-hidden text-slate-100">
          <div className="p-4 border-b border-[#334155] flex items-center justify-between gap-3 bg-[#1e293b]">
            <div>
              <h3 className="text-sm font-bold">{zh ? "生成代码与审计信息" : "Generated code and audit facts"}</h3>
              <p className="text-[10px] font-mono text-slate-400 mt-1">{selectedBundle?.bundle_id || "NO ARTIFACT"}</p>
            </div>
            {selectedBundle && (
              <div className="flex gap-2">
                <button type="button" onClick={() => void copyCode()} className="px-2.5 py-1.5 rounded-lg bg-slate-700 hover:bg-slate-600 text-[10px] font-semibold flex items-center gap-1 cursor-pointer">
                  {copied ? <Check className="w-3 h-3 text-lime-300" /> : <Copy className="w-3 h-3" />}
                  {copied ? (zh ? "已复制" : "Copied") : (zh ? "复制" : "Copy")}
                </button>
                <a href={selectedBundle.artifact_uri} download={selectedBundle.filename} className="px-2.5 py-1.5 rounded-lg bg-[#2aa198] hover:bg-[#238b83] text-[10px] font-semibold flex items-center gap-1">
                  <Download className="w-3 h-3" /> {zh ? "下载 .py" : "Download .py"}
                </a>
              </div>
            )}
          </div>
          {selectedBundle ? (
            <div>
              <div className="px-4 py-3 border-b border-[#334155] grid grid-cols-1 md:grid-cols-2 gap-2 text-[10px]">
                <div><span className="text-slate-500">VULNERABILITY</span><div className="font-mono text-cyan-300 break-all">{selectedBundle.vulnerability_id}</div></div>
                <div><span className="text-slate-500">SHA-256</span><div className="font-mono text-cyan-300 break-all">{selectedBundle.target_sha256}</div></div>
                <div><span className="text-slate-500">VERIFICATION</span><div className="font-mono text-lime-300">{selectedBundle.verification_status.toUpperCase()} · {(selectedBundle.verification_confidence * 100).toFixed(0)}%</div></div>
                <div><span className="text-slate-500">SAFETY</span><div className="font-mono text-amber-200">NO EXEC · NO NET · NO CMD</div></div>
              </div>
              <pre className="p-4 overflow-auto max-h-[520px] text-[11px] leading-relaxed font-mono text-slate-200 whitespace-pre">{selectedBundle.code}</pre>
              {bundles.length > 1 && (
                <div className="p-3 border-t border-[#334155] flex flex-wrap gap-1.5">
                  {bundles.map((bundle) => (
                    <button key={bundle.bundle_id} type="button" onClick={() => setSelectedBundleId(bundle.bundle_id)} className={`px-2 py-1 rounded text-[9px] font-mono cursor-pointer ${selectedBundle.bundle_id === bundle.bundle_id ? "bg-[#2aa198] text-white" : "bg-slate-700 text-slate-300"}`}>
                      {bundle.vulnerability_id.slice(-8)} · {new Date(bundle.created_at).toLocaleTimeString()}
                    </button>
                  ))}
                </div>
              )}
            </div>
          ) : (
            <div className="min-h-[440px] flex items-center justify-center text-center p-8 text-slate-500">
              <div><Code2 className="w-10 h-10 mx-auto mb-3 opacity-40" /><p className="text-xs">{zh ? "选择已确认漏洞并生成后，在这里检查和下载复现代码。" : "Generate a replay for a confirmed finding to inspect and download it here."}</p></div>
            </div>
          )}
        </section>
      </div>
    </div>
  );
};
