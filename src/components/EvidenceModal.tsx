import React from "react";
import { X, Database, ShieldCheck, FileCode, Bug, Terminal } from "lucide-react";
import { Evidence } from "../types.js";

interface EvidenceModalProps {
  isOpen: boolean;
  onClose: () => void;
  evidenceList: Evidence[];
  selectedEvidence?: Evidence | null;
}

export const EvidenceModal: React.FC<EvidenceModalProps> = ({
  isOpen,
  onClose,
  evidenceList,
  selectedEvidence: initialSelected,
}) => {
  const [selected, setSelected] = React.useState<Evidence | null>(
    initialSelected || evidenceList[0] || null
  );

  React.useEffect(() => {
    if (initialSelected) {
      setSelected(initialSelected);
    } else if (evidenceList.length > 0 && !selected) {
      setSelected(evidenceList[0]);
    }
  }, [initialSelected, evidenceList]);

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-4xl max-h-[85vh] flex flex-col shadow-2xl overflow-hidden animate-in fade-in zoom-in-95 duration-150">
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
              <Database className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-base font-bold text-slate-100">Evidence Chain Explorer</h3>
              <p className="text-xs text-slate-400">
                Audited artifacts, crash dumps, and taint paths supporting vulnerability confirmation
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="w-8 h-8 rounded-lg bg-slate-800 hover:bg-slate-700 flex items-center justify-center text-slate-400 hover:text-slate-200 transition-colors cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Content Body */}
        <div className="flex-1 overflow-hidden grid grid-cols-1 md:grid-cols-12 divide-y md:divide-y-0 md:divide-x divide-slate-800">
          {/* Artifact List Sidebar */}
          <div className="md:col-span-4 p-4 overflow-y-auto space-y-2 bg-slate-950/40">
            <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block mb-2">
              Artifacts ({evidenceList.length})
            </span>
            {evidenceList.map((ev) => (
              <button
                key={ev.evidence_id}
                onClick={() => setSelected(ev)}
                className={`w-full p-3 rounded-lg border text-left transition-all cursor-pointer ${
                  selected?.evidence_id === ev.evidence_id
                    ? "bg-cyan-950/60 border-cyan-500/60 text-cyan-200 ring-1 ring-cyan-500/30"
                    : "bg-slate-900 border-slate-800 hover:border-slate-700 text-slate-300"
                }`}
              >
                <div className="flex items-center justify-between gap-1 text-[11px] font-mono text-cyan-400 mb-1">
                  <span>{ev.evidence_type}</span>
                  <span className="text-[10px] text-slate-400 font-sans">
                    {(ev.reliability * 100).toFixed(0)}% trust
                  </span>
                </div>
                <h5 className="text-xs font-medium text-slate-200 line-clamp-2">{ev.description}</h5>
                <span className="text-[10px] text-slate-400 block mt-1">By: {ev.created_by}</span>
              </button>
            ))}
          </div>

          {/* Selected Artifact Detail */}
          <div className="md:col-span-8 p-6 overflow-y-auto space-y-4">
            {selected ? (
              <>
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <div className="flex items-center gap-2 mb-1">
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-cyan-950 text-cyan-300 border border-cyan-800">
                        {selected.evidence_type}
                      </span>
                      <span className="font-mono text-xs text-slate-400">{selected.evidence_id}</span>
                    </div>
                    <h4 className="text-base font-bold text-slate-100">{selected.description}</h4>
                  </div>
                  <div className="text-right">
                    <span className="text-xs text-slate-400 block">Reliability Score</span>
                    <span className="text-base font-mono font-bold text-emerald-400">
                      {(selected.reliability * 100).toFixed(0)}%
                    </span>
                  </div>
                </div>

                {selected.artifact_path && (
                  <div className="p-2.5 rounded bg-slate-950 border border-slate-800 text-xs font-mono text-slate-300 flex items-center gap-2">
                    <FileCode className="w-4 h-4 text-cyan-400 shrink-0" />
                    <span>Path: {selected.artifact_path}</span>
                  </div>
                )}

                {/* Structured Payload Render */}
                <div>
                  <label className="text-xs font-semibold text-slate-400 block mb-2">
                    Artifact Payload & Execution Trace
                  </label>
                  <pre className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-slate-200 overflow-x-auto whitespace-pre-wrap leading-relaxed">
                    {JSON.stringify(selected.data, null, 2)}
                  </pre>
                </div>

                <div className="text-xs text-slate-400 flex items-center justify-between pt-2 border-t border-slate-800 font-mono">
                  <span>Source Agent: {selected.source}</span>
                  <span>Recorded: {new Date(selected.created_at).toLocaleString()}</span>
                </div>
              </>
            ) : (
              <div className="text-center py-12 text-slate-500 text-xs">
                Select an evidence artifact from the left panel to inspect details.
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
