// ==========================================================================
// TypeScript types — mapped from FastAPI OpenAPI response shapes
// Do NOT invent fields that do not exist in the backend contracts.
// ==========================================================================

export type TaskStatus =
  | 'created'
  | 'planning'
  | 'analyzing'
  | 'dynamic_testing'
  | 'profiling'
  | 'verifying'
  | 'reporting'
  | 'completed'
  | 'failed'

export interface TaskTarget {
  path: string
  target_type: 'source' | 'binary' | 'project' | 'archive'
}

export interface Task {
  task_id: string
  status: TaskStatus
  target: TaskTarget
  created_at: string | null
  updated_at: string | null
  completed_at: string | null
  error_message?: string | null
  metadata?: Record<string, unknown>
}

// ── Vulnerability Candidate / Finding ───────────────────────────────────────

export type VulnStatus =
  | 'CANDIDATE'
  | 'VERIFYING'
  | 'CONFIRMED'
  | 'REJECTED'
  | 'UNCERTAIN'

export interface VulnerabilityLocation {
  file?: string | null
  line_start?: number | null
  line_end?: number | null
  function_name?: string | null
  address?: string | null
}

export interface VulnerabilityCandidate {
  vulnerability_id: string
  task_id: string
  vulnerability_type: string
  cwe_id?: string | null
  title: string
  description?: string | null
  target?: string | null
  location?: VulnerabilityLocation | null
  source_agent: string
  confidence: number
  evidence_ids: string[]
  status: VulnStatus
  created_at?: string | null
}

// ── Evidence ─────────────────────────────────────────────────────────────────

export type EvidenceType =
  | 'SOURCE_LOCATION'
  | 'CODE_SNIPPET'
  | 'CALL_PATH'
  | 'DATA_FLOW'
  | 'TAINT_PATH'
  | 'BINARY_ADDRESS'
  | 'DISASSEMBLY'
  | 'CFG_PATH'
  | 'FUZZ_INPUT'
  | 'COVERAGE'
  | 'CRASH_LOG'
  | 'STACK_TRACE'
  | 'SANITIZER_OUTPUT'
  | 'RUNTIME_TRACE'
  | 'TOOL_RESULT'
  | 'MODEL_REASONING_SUMMARY'
  | 'VERIFICATION_RESULT'

export interface Evidence {
  evidence_id: string
  task_id: string
  evidence_type: EvidenceType
  source_agent?: string | null
  payload: Record<string, unknown>
  created_at?: string | null
}

// ── Trace / Events ───────────────────────────────────────────────────────────

export interface TraceEvent {
  event_id?: string | null
  event_type: string
  task_id: string
  sender?: string | null
  receiver?: string | null
  payload?: Record<string, unknown> | null
  created_at?: string | null
}

// ── Verification ─────────────────────────────────────────────────────────────

export interface VerificationResult {
  verification_id: string
  vulnerability_id: string
  task_id: string
  status: VulnStatus
  confidence: number
  rationale?: string | null
  evidence_ids: string[]
  created_at?: string | null
}

// ── Report ───────────────────────────────────────────────────────────────────

export interface ReportSummary {
  total_candidates?: number
  confirmed?: number
  rejected?: number
  uncertain?: number
  executive_summary?: string | null
}

export interface Report {
  report_id?: string
  task_id: string
  title?: string | null
  summary?: ReportSummary | null
  vulnerabilities?: VulnerabilityCandidate[]
  created_at?: string | null
}

// ── Health ───────────────────────────────────────────────────────────────────

export interface HealthResponse {
  status: string
  service?: string
  version?: string
}

// ── API Error ────────────────────────────────────────────────────────────────

export interface ApiError {
  code?: string
  message: string
  details?: unknown
}
