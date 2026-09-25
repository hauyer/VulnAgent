/** Contract types mirroring the FastAPI routes the UI consumes. */
export interface Target {
  target_id: string;
  path: string;
  target_type: string;
}

export interface Task {
  task_id: string;
  target: Target;
  status: string;
  created_at: string;
  updated_at: string;
  error: string | null;
  metadata: Record<string, unknown>;
}

export interface TraceEvent {
  event_type: string;
  task_id: string;
  producer: string;
  payload: Record<string, unknown>;
  timestamp: string;
}

export interface Finding {
  vulnerability_id: string;
  task_id: string;
  title: string;
  vulnerability_type: string;
  cwe_id: string;
  description: string;
  location: { file_path: string; line_start: number } | string;
  source_agent: string;
  source_type: string;
  confidence: number;
  severity: string;
  status: string;
  evidence_ids: string[];
}

export interface Evidence {
  evidence_id: string;
  task_id: string;
  evidence_type: string;
  source: string;
  description: string;
  artifact_path: string | null;
  data: Record<string, unknown>;
  reliability: number;
}

export interface Verification {
  vulnerability_id: string;
  task_id: string;
  status: string;
  confidence: number;
  evidence_ids: string[];
}

export interface ReviewNote {
  decision: "accepted" | "rejected" | "needs_followup";
  note: string;
}

/** "未运行 / 未确认 / 确认" 文案不可混淆：状态徽章用不同颜色区分。 */
export const STATUS_STYLES: Record<string, { label: string; cls: string }> = {
  PROFILING: { label: "分析中", cls: "bg-blue-100 text-blue-700" },
  PENDING: { label: "等待", cls: "bg-gray-100 text-gray-600" },
  RUNNING: { label: "运行中", cls: "bg-blue-100 text-blue-700" },
  COMPLETED: { label: "已完成", cls: "bg-green-100 text-green-700" },
  FAILED: { label: "失败", cls: "bg-red-100 text-red-700" },
  CANCELLED: { label: "已取消", cls: "bg-gray-200 text-gray-500" },
};

export function statusStyle(status: string): { label: string; cls: string } {
  return (
    STATUS_STYLES[status] ?? {
      label: status,
      cls: "bg-gray-100 text-gray-600",
    }
  );
}
