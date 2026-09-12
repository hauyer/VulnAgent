import React, { useState } from "react";
import {
  Terminal,
  Play,
  Copy,
  Check,
  RotateCcw,
  Sparkles,
  ExternalLink,
  Code,
  Shield,
  Layers,
} from "lucide-react";
import { useTranslation } from "../i18n.js";

interface ApiEndpoint {
  method: "GET" | "POST";
  path: string;
  descriptionEn: string;
  descriptionZh: string;
  body?: unknown;
}

interface ApiConsoleViewProps {
  taskId: string;
}

interface ApiConsoleResponse {
  status: number;
  statusText: string;
  data?: unknown;
  error?: string;
}

export const ApiConsoleView: React.FC<ApiConsoleViewProps> = ({ taskId }) => {
  const { t, language } = useTranslation();

  const endpoints: ApiEndpoint[] = [
    {
      method: "GET",
      path: "/api/health",
      descriptionEn: "Check system health and runtime environment",
      descriptionZh: "检查后端健康状态与容器运行时环境",
    },
    {
      method: "GET",
      path: "/api/tasks",
      descriptionEn: "List all active vulnerability audit tasks",
      descriptionZh: "获取当前所有漏洞审计分析任务列表",
    },
    {
      method: "GET",
      path: "/api/acceptance/batches",
      descriptionEn: "List model, task, file and report batch associations",
      descriptionZh: "查询模型、任务、文件、验收批次与报告关联",
    },
    {
      method: "GET",
      path: `/api/tasks/${taskId}`,
      descriptionEn: "Fetch task details and target metadata",
      descriptionZh: "获取指定审计任务详情与目标程序元数据",
    },
    {
      method: "POST",
      path: `/api/tasks/${taskId}/run`,
      descriptionEn: "Trigger the autonomous multi-agent pipeline",
      descriptionZh: "触发多智能体协同漏洞挖掘全流程流水线",
    },
    {
      method: "GET",
      path: `/api/tasks/${taskId}/findings`,
      descriptionEn: "Retrieve vulnerability candidates and confirmed findings",
      descriptionZh: "查询已挖掘的候选漏洞与已确认漏洞清单",
    },
    {
      method: "GET",
      path: `/api/tasks/${taskId}/evidence`,
      descriptionEn: "Retrieve verified evidence chain artifacts",
      descriptionZh: "检索多智能体存证的证据链实体与崩溃上下文",
    },
    {
      method: "GET",
      path: `/api/tasks/${taskId}/verifications`,
      descriptionEn: "Retrieve independent verification verdicts",
      descriptionZh: "查询独立漏洞复核结果",
    },
    {
      method: "GET",
      path: `/api/tasks/${taskId}/poc`,
      descriptionEn: "List controlled PoC evidence-replay artifacts",
      descriptionZh: "查询已确认漏洞的受控 PoC 复现代码",
    },
    {
      method: "GET",
      path: `/api/tasks/${taskId}/report`,
      descriptionEn: "Get executive security audit report",
      descriptionZh: "生成并获取最终安全审计评估总报告",
    },
    {
      method: "GET",
      path: `/api/tasks/${taskId}/trace`,
      descriptionEn: "Get full chronological domain event audit log",
      descriptionZh: "拉取全流程 AgentMessage 与领域事件审计流",
    },
  ];

  const [selectedEndpoint, setSelectedEndpoint] = useState<ApiEndpoint>(endpoints[0]);
  const [response, setResponse] = useState<ApiConsoleResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [latency, setLatency] = useState<number | null>(null);
  const [copied, setCopied] = useState(false);

  const handleExecute = async () => {
    setLoading(true);
    setResponse(null);
    const start = performance.now();

    try {
      const res = await fetch(selectedEndpoint.path, {
        method: selectedEndpoint.method,
        headers: {
          "Content-Type": "application/json",
        },
        body: selectedEndpoint.body ? JSON.stringify(selectedEndpoint.body) : undefined,
      });

      const end = performance.now();
      setLatency(Math.round(end - start));

      const data = await res.json();
      setResponse({
        status: res.status,
        statusText: res.statusText,
        data,
      });
    } catch (err: unknown) {
      setResponse({
        status: 500,
        statusText: "Client Fetch Error",
        error: err instanceof Error ? err.message : "Unknown client error",
      });
    } finally {
      setLoading(false);
    }
  };

  const curlCommand = `curl -X ${selectedEndpoint.method} "http://127.0.0.1:8000${selectedEndpoint.path}" ${
    selectedEndpoint.body ? `-H "Content-Type: application/json" -d '${JSON.stringify(selectedEndpoint.body)}'` : ""
  }`;

  const handleCopyCurl = () => {
    navigator.clipboard.writeText(curlCommand);
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
              <Terminal className="w-3.5 h-3.5" />
            </div>
            <h2 className="text-base font-bold text-[#2b3638]">{t("apiTitle")}</h2>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#eef7f6] text-[#2aa198] border border-[#bfe3e0] font-semibold">
              OpenAPI 3.1 • FastAPI :8000
            </span>
          </div>
          <p className="text-xs text-[#586e75]">
            {t("apiSubtitle")}
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={handleCopyCurl}
            className="px-3 py-1.5 rounded-lg bg-[#f5eed9] hover:bg-[#eee8d5] border border-[#dfd6bf] text-xs font-mono text-[#586e75] flex items-center gap-1.5 transition-colors cursor-pointer"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-[#859900]" /> : <Copy className="w-3.5 h-3.5 text-[#2aa198]" />}
            <span>{copied ? (language === "zh" ? "已复制 cURL" : "Copied cURL") : (language === "zh" ? "复制 cURL" : "Copy cURL")}</span>
          </button>
        </div>
      </div>

      {/* Main Grid: Endpoint Selector + Console Runner */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Endpoints List */}
        <div className="lg:col-span-4 space-y-2">
          <span className="text-[10px] font-semibold text-[#586e75] uppercase tracking-wider block px-1">
            {t("apiEndpointsList")}
          </span>
          <div className="space-y-1.5 font-mono text-xs">
            {endpoints.map((ep) => {
              const isSelected = selectedEndpoint.path === ep.path && selectedEndpoint.method === ep.method;
              return (
                <button
                  key={`${ep.method}-${ep.path}`}
                  onClick={() => setSelectedEndpoint(ep)}
                  className={`w-full p-3 rounded-xl border text-left transition-all cursor-pointer flex items-center justify-between gap-2 ${
                    isSelected
                      ? "bg-[#eef7f6] border-[#2aa198] text-[#2b3638] shadow-sm font-semibold"
                      : "bg-[#fdfaf3] border-[#dfd6bf] text-[#586e75] hover:bg-[#fcf8ed] hover:text-[#2b3638]"
                  }`}
                >
                  <div className="truncate">
                    <div className="flex items-center gap-2">
                      <span
                        className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                          ep.method === "GET"
                            ? "bg-[#eef4fb] text-[#268bd2] border border-[#b9d6f3]"
                            : "bg-[#edf5d3] text-[#859900] border border-[#cce38d]"
                        }`}
                      >
                        {ep.method}
                      </span>
                      <span className="truncate text-[#2b3638] font-medium">{ep.path}</span>
                    </div>
                    <span className="text-[10px] text-[#586e75] font-sans block mt-1 truncate">
                      {language === "zh" ? ep.descriptionZh : ep.descriptionEn}
                    </span>
                  </div>
                </button>
              );
            })}
          </div>
        </div>

        {/* Right Runner & Output Panel */}
        <div className="lg:col-span-8 space-y-4">
          <div className="p-6 rounded-2xl bg-[#fdfaf3] border border-[#dfd6bf] shadow-sm space-y-4 font-mono text-xs">
            {/* Request Bar */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-3 bg-[#f5eed9] rounded-xl border border-[#dfd6bf]">
              <div className="flex items-center gap-2 truncate">
                <span
                  className={`px-2 py-1 rounded text-xs font-bold ${
                    selectedEndpoint.method === "GET"
                      ? "bg-[#eef4fb] text-[#268bd2] border border-[#b9d6f3]"
                      : "bg-[#edf5d3] text-[#859900] border border-[#cce38d]"
                  }`}
                >
                  {selectedEndpoint.method}
                </span>
                <span className="text-[#2b3638] font-semibold select-all truncate">{selectedEndpoint.path}</span>
              </div>

              <button
                onClick={handleExecute}
                disabled={loading}
                className="px-4 py-2 rounded-lg bg-[#2aa198] hover:bg-[#238b83] text-white font-bold text-xs flex items-center gap-1.5 transition-colors cursor-pointer shrink-0 disabled:opacity-50 shadow-xs"
              >
                <Play className={`w-3.5 h-3.5 fill-current ${loading ? "animate-spin" : ""}`} />
                <span>{loading ? t("apiSending") : t("apiSendRequest")}</span>
              </button>
            </div>

            {/* Generated cURL command */}
            <div>
              <span className="text-[10px] text-[#586e75] uppercase font-mono block mb-1">
                {t("apiCurlTitle")}
              </span>
              <pre className="p-3 rounded-lg bg-[#f5eed9] border border-[#dfd6bf] text-[#2aa198] select-all overflow-x-auto text-[11px] font-semibold">
                {curlCommand}
              </pre>
            </div>

            {/* Response Console */}
            <div>
              <div className="flex items-center justify-between mb-1.5">
                <span className="text-[10px] text-[#586e75] uppercase font-mono">{t("apiLiveResponse")}</span>
                {response && (
                  <div className="flex items-center gap-2 text-[11px]">
                    <span
                      className={`px-2 py-0.5 rounded font-bold ${
                        response.status >= 200 && response.status < 300
                          ? "bg-[#edf5d3] text-[#859900] border border-[#cce38d]"
                          : "bg-[#fce8e6] text-[#dc322f] border border-[#f5b8b5]"
                      }`}
                    >
                      {response.status} {response.statusText}
                    </span>
                    {latency !== null && (
                      <span className="text-[#586e75]">{latency} ms</span>
                    )}
                  </div>
                )}
              </div>

              <pre className="p-4 rounded-xl bg-[#f5eed9] border border-[#dfd6bf] text-[#2b3638] overflow-x-auto max-h-[380px] leading-relaxed text-[11px]">
                {loading ? (
                  <span className="text-[#2aa198] animate-pulse">{t("apiWaitingResponse")}</span>
                ) : response ? (
                  JSON.stringify(response.data || response.error, null, 2)
                ) : (
                  <span className="text-[#839496]">{t("apiPromptTest")}</span>
                )}
              </pre>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
