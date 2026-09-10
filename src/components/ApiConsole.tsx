import React, { useState } from "react";
import { X, Play, Terminal, Copy, Check } from "lucide-react";

interface ApiConsoleProps {
  isOpen: boolean;
  onClose: () => void;
  defaultTaskId?: string;
}

const ENDPOINTS = [
  { method: "GET", path: "/health", body: null, label: "Health Check" },
  { method: "GET", path: "/tasks", body: null, label: "List All Tasks" },
  {
    method: "POST",
    path: "/tasks",
    body: JSON.stringify({ target_path: "sample.c", target_type: "source" }, null, 2),
    label: "Create Task (Source)",
  },
  { method: "GET", path: "/tasks/{task_id}", body: null, label: "Get Task Detail" },
  { method: "POST", path: "/tasks/{task_id}/run", body: null, label: "Run Pipeline" },
  { method: "GET", path: "/tasks/{task_id}/findings", body: null, label: "Get Findings" },
  { method: "GET", path: "/tasks/{task_id}/evidence", body: null, label: "Get Evidence Chain" },
  { method: "GET", path: "/tasks/{task_id}/report", body: null, label: "Get Audit Report" },
  { method: "GET", path: "/tasks/{task_id}/trace", body: null, label: "Get Trace Events" },
];

export const ApiConsole: React.FC<ApiConsoleProps> = ({ isOpen, onClose, defaultTaskId }) => {
  const [selectedEndpoint, setSelectedEndpoint] = useState(ENDPOINTS[0]);
  const [taskIdInput, setTaskIdInput] = useState(defaultTaskId || "task-demo-buffer-overflow-01");
  const [requestBody, setRequestBody] = useState<string>("");
  const [responseStatus, setResponseStatus] = useState<number | null>(null);
  const [responseHeaders, setResponseHeaders] = useState<Record<string, string>>({});
  const [responseData, setResponseData] = useState<any>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [copied, setCopied] = useState(false);

  React.useEffect(() => {
    if (defaultTaskId) {
      setTaskIdInput(defaultTaskId);
    }
  }, [defaultTaskId]);

  if (!isOpen) return null;

  const resolvedPath = selectedEndpoint.path.replace("{task_id}", taskIdInput);

  const handleExecute = async () => {
    setIsLoading(true);
    setResponseData(null);
    setResponseStatus(null);
    try {
      const options: RequestInit = {
        method: selectedEndpoint.method,
        headers: {
          "Content-Type": "application/json",
        },
      };

      if (selectedEndpoint.method === "POST" && (requestBody || selectedEndpoint.body)) {
        options.body = requestBody || selectedEndpoint.body || undefined;
      }

      const res = await fetch(resolvedPath, options);
      setResponseStatus(res.status);

      const json = await res.json().catch(() => null);
      setResponseData(json);
    } catch (err: any) {
      setResponseStatus(500);
      setResponseData({ error: err.message || "Failed to fetch" });
    } finally {
      setIsLoading(false);
    }
  };

  const curlCommand = `curl -X ${selectedEndpoint.method} http://localhost:3000${resolvedPath} ${
    selectedEndpoint.method === "POST" && (requestBody || selectedEndpoint.body)
      ? `-H "Content-Type: application/json" -d '${(requestBody || selectedEndpoint.body || "").replace(/\n/g, "")}'`
      : ""
  }`;

  const handleCopy = () => {
    navigator.clipboard.writeText(curlCommand);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-4xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden animate-in fade-in zoom-in-95 duration-150">
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
              <Terminal className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-base font-bold text-slate-100">REST API Explorer</h3>
              <p className="text-xs text-slate-400">
                Directly execute VulnAgent FastAPI/Express REST contracts & verify endpoints
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

        {/* Body */}
        <div className="flex-1 overflow-hidden grid grid-cols-1 md:grid-cols-12 divide-y md:divide-y-0 md:divide-x divide-slate-800">
          {/* Endpoint Sidebar */}
          <div className="md:col-span-4 p-4 overflow-y-auto space-y-1.5 bg-slate-950/40">
            <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block mb-2">
              Endpoints
            </span>
            {ENDPOINTS.map((ep, idx) => (
              <button
                key={idx}
                onClick={() => {
                  setSelectedEndpoint(ep);
                  setRequestBody(ep.body || "");
                  setResponseData(null);
                  setResponseStatus(null);
                }}
                className={`w-full p-2.5 rounded-lg border text-left transition-all cursor-pointer ${
                  selectedEndpoint.path === ep.path && selectedEndpoint.method === ep.method
                    ? "bg-cyan-950/60 border-cyan-500/50 text-cyan-200 ring-1 ring-cyan-500/30"
                    : "bg-slate-900 border-slate-800 hover:border-slate-700 text-slate-300"
                }`}
              >
                <div className="flex items-center gap-2 mb-1">
                  <span
                    className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-bold ${
                      ep.method === "GET"
                        ? "bg-emerald-950 text-emerald-400 border border-emerald-800"
                        : "bg-blue-950 text-blue-400 border border-blue-800"
                    }`}
                  >
                    {ep.method}
                  </span>
                  <span className="text-xs font-semibold text-slate-200">{ep.label}</span>
                </div>
                <div className="text-[11px] font-mono text-slate-400 truncate">{ep.path}</div>
              </button>
            ))}
          </div>

          {/* Interactive Request & Response Area */}
          <div className="md:col-span-8 p-6 overflow-y-auto space-y-4">
            {/* Target Path & Execute Button */}
            <div className="space-y-3">
              {selectedEndpoint.path.includes("{task_id}") && (
                <div>
                  <label className="text-xs font-semibold text-slate-400 block mb-1">task_id parameter</label>
                  <input
                    type="text"
                    value={taskIdInput}
                    onChange={(e) => setTaskIdInput(e.target.value)}
                    className="w-full px-3 py-1.5 bg-slate-950 border border-slate-700 rounded-lg text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
                    placeholder="task-demo-buffer-overflow-01"
                  />
                </div>
              )}

              <div className="flex items-center gap-2">
                <div className="flex-1 px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono flex items-center gap-2 text-slate-300">
                  <span
                    className={`font-bold ${
                      selectedEndpoint.method === "GET" ? "text-emerald-400" : "text-blue-400"
                    }`}
                  >
                    {selectedEndpoint.method}
                  </span>
                  <span>{resolvedPath}</span>
                </div>

                <button
                  onClick={handleExecute}
                  disabled={isLoading}
                  className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-semibold text-xs flex items-center gap-1.5 transition-colors disabled:opacity-50 cursor-pointer shadow-md"
                >
                  <Play className="w-3.5 h-3.5 fill-current" />
                  <span>{isLoading ? "Executing..." : "Send"}</span>
                </button>
              </div>

              {/* cURL Copy */}
              <div className="flex items-center justify-between p-2 rounded bg-slate-950 border border-slate-800 text-[11px] font-mono text-slate-400">
                <span className="truncate mr-2">{curlCommand}</span>
                <button
                  onClick={handleCopy}
                  className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 flex items-center gap-1 shrink-0 cursor-pointer"
                >
                  {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  <span>{copied ? "Copied" : "Copy cURL"}</span>
                </button>
              </div>

              {/* Request Body if POST */}
              {selectedEndpoint.method === "POST" && (
                <div>
                  <label className="text-xs font-semibold text-slate-400 block mb-1">
                    Request Payload (JSON)
                  </label>
                  <textarea
                    value={requestBody}
                    onChange={(e) => setRequestBody(e.target.value)}
                    rows={4}
                    placeholder="{}"
                    className="w-full p-3 bg-slate-950 border border-slate-700 rounded-lg text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
                  />
                </div>
              )}
            </div>

            {/* Response Section */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-semibold text-slate-400">Response Payload</span>
                {responseStatus !== null && (
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                      responseStatus >= 200 && responseStatus < 300
                        ? "bg-emerald-950 text-emerald-300 border border-emerald-800"
                        : "bg-rose-950 text-rose-300 border border-rose-800"
                    }`}
                  >
                    Status: {responseStatus}
                  </span>
                )}
              </div>

              <pre className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-slate-200 max-h-[300px] overflow-auto whitespace-pre-wrap">
                {responseData !== null
                  ? JSON.stringify(responseData, null, 2)
                  : "// Click 'Send' to test the endpoint response."}
              </pre>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
