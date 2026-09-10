import React, { useState, useRef, useEffect } from "react";
import {
  Activity,
  Terminal,
  Search,
  Filter,
  ArrowDown,
  Copy,
  Check,
  Play,
  RotateCcw,
  Clock,
  Layers,
  Sparkles,
  ChevronDown,
  ChevronRight,
} from "lucide-react";
import { DomainEvent } from "../types.js";
import { useTranslation } from "../i18n.js";

interface EventTraceViewProps {
  events: DomainEvent[];
  taskId: string;
  onTriggerRun: () => void;
  isRunning: boolean;
}

export const EventTraceView: React.FC<EventTraceViewProps> = ({
  events,
  taskId,
  onTriggerRun,
  isRunning,
}) => {
  const { t, language } = useTranslation();
  const [filterType, setFilterType] = useState<string>("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [autoScroll, setAutoScroll] = useState(true);
  const [expandedEvents, setExpandedEvents] = useState<Record<string, boolean>>({});
  const [copied, setCopied] = useState(false);
  const scrollBottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (autoScroll && scrollBottomRef.current) {
      scrollBottomRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [events, autoScroll]);

  const toggleExpand = (id: string) => {
    setExpandedEvents((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  const filteredEvents = events.filter((ev) => {
    const matchesFilter = filterType === "all" || ev.event_type === filterType;
    const matchesSearch =
      ev.event_type.toLowerCase().includes(searchQuery.toLowerCase()) ||
      JSON.stringify(ev.payload).toLowerCase().includes(searchQuery.toLowerCase()) ||
      ev.event_id.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesFilter && matchesSearch;
  });

  const getEventBadgeColor = (type: string) => {
    if (type.includes("confirmed")) return "bg-[#edf5d3] text-[#859900] border-[#cce38d]";
    if (type.includes("started") || type.includes("routed")) return "bg-[#eef7f6] text-[#2aa198] border-[#bfe3e0]";
    if (type.includes("evidence")) return "bg-[#eef4fb] text-[#268bd2] border-[#b9d6f3]";
    if (type.includes("candidate")) return "bg-[#fbf4e6] text-[#b58900] border-[#ecd8a6]";
    if (type.includes("completed")) return "bg-[#f5eefb] text-[#6c71c4] border-[#d8c8f0]";
    return "bg-[#eee8d5] text-[#586e75] border-[#dfd6bf]";
  };

  const handleCopyLogs = () => {
    navigator.clipboard.writeText(JSON.stringify(events, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="p-5 rounded-2xl bg-[#f4eedb] border border-[#dfd6bf] shadow-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <div className="w-6 h-6 rounded-lg bg-[#2aa198]/10 border border-[#2aa198]/30 flex items-center justify-center text-[#2aa198]">
              <Activity className="w-3.5 h-3.5" />
            </div>
            <h2 className="text-base font-bold text-[#2b3638]">{t("traceTitle")}</h2>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#eef7f6] text-[#2aa198] border border-[#bfe3e0] font-semibold">
              Event Sourcing Protocol
            </span>
          </div>
          <p className="text-xs text-[#586e75]">
            {t("traceSubtitle")}
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => setAutoScroll(!autoScroll)}
            className={`px-3 py-1.5 rounded-lg border text-xs font-mono flex items-center gap-1.5 transition-colors cursor-pointer ${
              autoScroll
                ? "bg-[#edf5d3] border-[#cce38d] text-[#859900]"
                : "bg-[#f5eed9] border-[#dfd6bf] text-[#586e75]"
            }`}
          >
            <span className={`w-2 h-2 rounded-full ${autoScroll ? "bg-[#859900] animate-pulse" : "bg-[#839496]"}`} />
            <span>{language === "zh" ? (autoScroll ? "自动滚动: 开启" : "自动滚动: 关闭") : `Auto-Scroll ${autoScroll ? "ON" : "OFF"}`}</span>
          </button>

          <button
            onClick={handleCopyLogs}
            className="px-3 py-1.5 rounded-lg bg-[#f5eed9] hover:bg-[#eee8d5] border border-[#dfd6bf] text-xs font-mono text-[#586e75] flex items-center gap-1.5 transition-colors cursor-pointer"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-[#859900]" /> : <Copy className="w-3.5 h-3.5 text-[#2aa198]" />}
            <span>{copied ? (language === "zh" ? "已导出 JSON" : "Copied JSON") : "JSON"}</span>
          </button>
        </div>
      </div>

      {/* Terminal Window Container */}
      <div className="rounded-2xl bg-[#fdfaf3] border border-[#dfd6bf] shadow-sm overflow-hidden font-mono text-xs flex flex-col">
        {/* Terminal Titlebar */}
        <div className="p-3 bg-[#f4eedb] border-b border-[#dfd6bf] flex flex-col sm:flex-row sm:items-center justify-between gap-3 px-4">
          <div className="flex items-center gap-2">
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-[#dc322f]" />
              <span className="w-2.5 h-2.5 rounded-full bg-[#b58900]" />
              <span className="w-2.5 h-2.5 rounded-full bg-[#859900]" />
            </div>
            <span className="text-[#586e75] text-[11px] ml-2 font-mono font-medium">
              telemetry@vulnagent:~# stream --task={taskId}
            </span>
          </div>

          <div className="flex items-center gap-2">
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-[#839496] absolute left-2.5 top-2" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder={language === "zh" ? "检索事件流、载荷..." : "Grep events..."}
                className="pl-8 pr-2.5 py-1 bg-[#fdfaf3] border border-[#dfd6bf] rounded-lg text-[11px] font-mono text-[#2b3638] placeholder:text-[#839496] focus:outline-none focus:border-[#2aa198]"
              />
            </div>

            <select
              value={filterType}
              onChange={(e) => setFilterType(e.target.value)}
              className="bg-[#fdfaf3] border border-[#dfd6bf] text-[#2b3638] text-[11px] font-mono rounded-lg px-2 py-1 focus:outline-none cursor-pointer"
            >
              <option value="all">{language === "zh" ? "全部事件类型" : "ALL EVENTS"}</option>
              <option value="task_started">task_started</option>
              <option value="agent_routed">agent_routed</option>
              <option value="candidate_created">candidate_created</option>
              <option value="evidence_added">evidence_added</option>
              <option value="candidate_confirmed">candidate_confirmed</option>
              <option value="task_completed">task_completed</option>
            </select>
          </div>
        </div>

        {/* Logs Stream */}
        <div className="p-4 space-y-2 max-h-[600px] overflow-y-auto">
          {filteredEvents.length === 0 ? (
            <div className="p-12 text-center text-[#839496] font-mono text-xs">
              {language === "zh" ? "未检索到匹配的领域事件记录" : "No domain events recorded matching filter."}
            </div>
          ) : (
            filteredEvents.map((ev, index) => {
              const isExpanded = !!expandedEvents[ev.event_id];
              return (
                <div
                  key={ev.event_id || index}
                  className="p-2.5 rounded-lg bg-[#fcf8ed] hover:bg-[#f5eed9] border border-[#dfd6bf] transition-colors"
                >
                  <div
                    onClick={() => toggleExpand(ev.event_id)}
                    className="flex items-center justify-between gap-3 cursor-pointer select-none flex-wrap"
                  >
                    <div className="flex items-center gap-2 flex-wrap">
                      <button className="text-[#839496] hover:text-[#2b3638]">
                        {isExpanded ? (
                          <ChevronDown className="w-3.5 h-3.5 text-[#2aa198]" />
                        ) : (
                          <ChevronRight className="w-3.5 h-3.5" />
                        )}
                      </button>

                      <span className="text-[10px] text-[#839496] font-mono">
                        {new Date(ev.timestamp).toLocaleTimeString([], { hour12: false })}
                      </span>

                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase border ${getEventBadgeColor(
                          ev.event_type
                        )}`}
                      >
                        {ev.event_type}
                      </span>

                      <span className="text-[11px] text-[#2b3638] truncate max-w-md">
                        {ev.payload?.summary ||
                          ev.payload?.description ||
                          ev.payload?.route ||
                          ev.payload?.vulnerability_id ||
                          ev.payload?.evidence_type ||
                          JSON.stringify(ev.payload)}
                      </span>
                    </div>

                    <span className="text-[10px] text-[#839496] font-mono">
                      {ev.event_id}
                    </span>
                  </div>

                  {isExpanded && (
                    <div className="mt-2.5 pt-2.5 border-t border-[#dfd6bf]">
                      <span className="text-[10px] text-[#586e75] uppercase block mb-1">
                        {language === "zh" ? "结构化事件载荷数据 (Payload):" : "Structured Payload:"}
                      </span>
                      <pre className="p-3 rounded-lg bg-[#f5eed9] border border-[#dfd6bf] text-[#2b3638] text-[11px] font-mono overflow-x-auto">
                        {JSON.stringify(ev.payload, null, 2)}
                      </pre>
                    </div>
                  )}
                </div>
              );
            })
          )}
          <div ref={scrollBottomRef} />
        </div>

        {/* Footer Status */}
        <div className="p-2.5 bg-[#f4eedb] border-t border-[#dfd6bf] flex items-center justify-between text-[11px] text-[#586e75] px-4">
          <div className="flex items-center gap-2 font-mono">
            <span className="w-2 h-2 rounded-full bg-[#2aa198] animate-pulse" />
            <span>
              {language === "zh" ? `遥测缓冲流: 共 ${events.length} 条存证记录` : `Telemetry buffer: ${events.length} records`}
            </span>
          </div>
          <span className="font-mono text-[10px] text-[#839496]">
            {language === "zh" ? "点击事件行可展开查看结构化载荷" : "Press event row to inspect payload"}
          </span>
        </div>
      </div>
    </div>
  );
};
