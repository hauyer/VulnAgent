export type TargetType = "source" | "binary" | "project" | "archive";

export type TaskStatus =
  | "created"
  | "profiling"
  | "planning"
  | "analyzing"
  | "dynamic_testing"
  | "verifying"
  | "reporting"
  | "completed"
  | "failed";

export interface Target {
  target_id: string;
  path: string;
  target_type: TargetType;
  language?: string | null;
  file_format?: string | null;
  metadata?: Record<string, any>;
}

export interface Task {
  task_id: string;
  target: Target;
  status: TaskStatus;
  created_at: string;
  updated_at: string;
  error?: string | null;
  metadata?: Record<string, any>;
}

export type VulnerabilityStatus =
  | "candidate"
  | "verifying"
  | "confirmed"
  | "rejected"
  | "uncertain";

export interface VulnerabilityLocation {
  file_path?: string | null;
  function_name?: string | null;
  line_start?: number | null;
  line_end?: number | null;
  binary_address?: string | null;
  module_name?: string | null;
}

export interface VulnerabilityCandidate {
  vulnerability_id: string;
  task_id: string;
  title: string;
  vulnerability_type: string;
  cwe_id?: string | null;
  description: string;
  target_id: string;
  location?: VulnerabilityLocation | null;
  source_agent: string;
  source_type?: string | null;
  producer?: string | null;
  confidence: number;
  severity?: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO" | null;
  evidence_ids: string[];
  status: VulnerabilityStatus;
  metadata?: Record<string, any>;
}

export type EvidenceType =
  | "source_location"
  | "code_snippet"
  | "call_path"
  | "data_flow"
  | "taint_path"
  | "binary_address"
  | "disassembly"
  | "cfg_path"
  | "fuzz_input"
  | "coverage"
  | "crash_log"
  | "stack_trace"
  | "sanitizer_output"
  | "runtime_trace"
  | "tool_result"
  | "model_reasoning_summary"
  | "verification_result";

export interface Evidence {
  evidence_id: string;
  task_id: string;
  evidence_type: EvidenceType;
  source: string;
  description: string;
  artifact_path?: string | null;
  data: Record<string, any>;
  reliability: number;
  created_by: string;
  created_at: string;
}

export interface DomainEvent {
  event_id: string;
  task_id: string;
  event_type: string;
  payload: Record<string, any>;
  timestamp: string;
}

export interface ReportResult {
  task_id: string;
  content: {
    summary?: string;
    executive_summary?: string;
    target_info?: Record<string, any>;
    metrics?: {
      total_candidates: number;
      confirmed_vulnerabilities: number;
      rejected_false_positives: number;
      uncertain_findings: number;
      evidence_count: number;
    };
    severity_breakdown?: {
      critical: number;
      high: number;
      medium: number;
      low: number;
    };
    findings?: VulnerabilityCandidate[];
    recommendations?: string[];
  };
  artifact_uri?: string | null;
  metadata?: Record<string, any>;
}

export type ActiveTab =
  | "dashboard"
  | "topology"
  | "evidence"
  | "vulnerabilities"
  | "report"
  | "trace"
  | "api";

export interface AgentNodeInfo {
  id: string;
  name: string;
  role: string;
  module: string;
  category: "orchestration" | "analysis" | "testing" | "verification" | "reporting";
  status: "idle" | "active" | "completed" | "bypassed";
  description: string;
  inputContract: string[];
  outputContract: string[];
  evidenceTypesProduced: EvidenceType[];
}
