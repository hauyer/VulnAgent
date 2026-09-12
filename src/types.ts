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

export interface UploadResult {
  original_name: string;
  stored_path: string;
  target_type: "source" | "binary";
  language?: string | null;
  file_format?: string | null;
  size_bytes: number;
  sha256: string;
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
  risk_subtype?: string | null;
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
  event_id?: string;
  task_id: string;
  event_type: string;
  producer: string;
  payload: Record<string, any>;
  timestamp: string;
}

export interface VerificationResult {
  vulnerability_id: string;
  task_id: string;
  status: VulnerabilityStatus;
  confidence: number;
  rationale: string;
  evidence_ids: string[];
  metadata: Record<string, unknown>;
}

export type HumanReviewDecision = "accepted" | "rejected" | "needs_followup";

export interface HumanReviewAnnotation {
  annotation_id: string;
  task_id: string;
  vulnerability_id: string;
  decision: HumanReviewDecision;
  note: string;
  reviewer: string;
  updated_at: string;
}

export interface StructuredReportFinding {
  finding: VulnerabilityCandidate;
  verification: VerificationResult | null;
  evidence: Evidence[];
  remediation: {
    guidance: string[];
    disclaimer: string;
  };
}

export type SoftwareCodeVulnerabilityType =
  | "integer_overflow"
  | "integer_underflow"
  | "integer_boundary_error"
  | "buffer_overflow"
  | "stack_buffer_overflow"
  | "heap_buffer_overflow"
  | "array_out_of_bounds"
  | "input_validation_missing"
  | "null_pointer_dereference"
  | "resource_leak"
  | "interface_access_control_missing"
  | "configuration_authorization_missing";

export interface SoftwareCodeDossier {
  dossier_id: string;
  finding_id: string;
  vulnerability_type: string;
  risk_subtype?: string | null;
  cwe_id?: string | null;
  title: string;
  risk_level: string;
  status: VulnerabilityStatus;
  source_location?: VulnerabilityLocation | null;
  control_flow_path: Array<Record<string, any>>;
  taint_path: Array<string | Record<string, any>>;
  candidate_rule: Record<string, any>;
  static_evidence: Evidence[];
  dynamic_validation?: Record<string, any> | null;
  agent_assessment?: Record<string, any> | null;
  independent_verification?: VerificationResult | null;
  remediation: Record<string, any>;
  evidence_chain: Array<Record<string, any>>;
  compliance_notice: string;
}

export interface ReportResult {
  task_id: string;
  content: {
    compliance_notice?: string;
    task: Task;
    summary: {
      finding_count: number;
      evidence_count: number;
      verification_count: number;
      findings_by_status: Record<VulnerabilityStatus, number>;
      findings_by_severity: Record<string, number>;
    };
    findings: StructuredReportFinding[];
    verifications: VerificationResult[];
    evidence_timeline: Array<Record<string, unknown>>;
    risk_summary: {
      headline: string;
      counts: {
        total: number;
        confirmed: number;
        rejected: number;
        pending: number;
      };
    };
    human_review?: {
      annotation_count: number;
      annotations: HumanReviewAnnotation[];
      note: string;
    };
    course_acceptance_summary?: {
      status_text: string;
      passed_groups: number;
      total_groups: number;
      groups: Array<{
        group_id: string;
        title: string;
        status: AcceptanceStatus;
        summary: string;
      }>;
      excluded_scope: string[];
    };
    acceptance_batches?: CustomAcceptanceBatch[];
    controlled_poc_bundles?: Array<Omit<ControlledPocBundle, "code">>;
    llm_vulnerability_scan?: {
      scan_id: string;
      model_name: string;
      local_only: boolean;
      requested_types: LLMVulnerabilityType[];
      summary: LLMScanSummary;
      probe_results: LLMProbeResult[];
      method: string;
      formal_verdict_note: string;
    };
    binary_protection_analysis?: {
      title: string;
      protection?: Record<string, any> | null;
      declared_protection?: string | null;
      strategy: string[];
      restoration: Record<string, any>;
      reverse_analysis: Record<string, any>;
      deobfuscation: Record<string, any>;
      evidence_chain: Array<Record<string, any>>;
    } | null;
    software_code_security?: {
      title: string;
      finding_count: number;
      risk_level_distribution: Record<string, number>;
      vulnerability_type_distribution: Record<string, number>;
      dossiers: SoftwareCodeDossier[];
      compliance_notice: string;
    };
  };
  artifact_uri?: string | null;
  metadata?: Record<string, any>;
}

export type ActiveTab =
  | "dashboard"
  | "topology"
  | "evidence"
  | "vulnerabilities"
  | "poc"
  | "report"
  | "trace"
  | "api"
  | "testlab"
  | "acceptance";

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

// ---- Course-test acceptance matrix (mirrors backend acceptance ViewModels) ----

export type AcceptanceStatus =
  | "not_run"
  | "running"
  | "pass"
  | "partial"
  | "fail"
  | "blocked";

export interface AcceptanceProviderStatus {
  provider: string;
  configured: boolean;
  is_mock: boolean;
  model?: string | null;
  base_url?: string | null;
  default_for_planner: boolean;
}

export interface AcceptanceProviderComparison {
  method: string;
  samples: number;
  true_positive: number;
  false_positive: number;
  true_negative: number;
  false_negative: number;
  precision: number;
  recall: number;
  f1: number;
  prompt_tokens?: number | null;
  completion_tokens?: number | null;
  total_tokens?: number | null;
  total_token_cost?: number | null;
  token_cost_currency?: string | null;
  mean_duration_seconds?: number | null;
  confirmed_finding_count: number;
  evidence_chain_coverage: number;
}

export interface LLMComparisonSummary {
  source: "canonical_artifact" | "published_baseline" | "unavailable" | string;
  snapshot_id?: string | null;
  generated_at?: string | null;
  benchmark_manifest_sha256?: string | null;
  manifest_matches?: boolean | null;
  metrics: AcceptanceProviderComparison[];
}

export interface BenchmarkCounts {
  source_samples: number;
  binary_samples: number;
  fuzz_scenarios: number;
}

export interface BinaryBenchmarkMetric {
  method: string;
  profile: string;
  samples: number;
  true_positive: number;
  false_positive: number;
  true_negative: number;
  false_negative: number;
  precision: number;
  recall: number;
  f1: number;
  false_positive_rate: number;
  evidence_chain_coverage: number;
  generated_at?: string | null;
}

export interface BenchmarkSummary {
  counts: BenchmarkCounts;
  stripped_binary?: BinaryBenchmarkMetric | null;
  elf_a?: ElfBenchmarkSummary | null;
}

export interface ElfBenchmarkSummary {
  fixture_count: number;
  family_count: number;
  profile_count: number;
  row_count: number;
  compiler_version?: string | null;
  compiler_machine?: string | null;
  target_execution?: boolean | null;
  generated_at?: string | null;
  profiles: BinaryBenchmarkMetric[];
}

export interface AcceptanceCondition {
  key: string;
  label: string;
  met: boolean;
  detail: string;
}

export interface AcceptanceTarget {
  sample_id: string;
  software_name: string;
  author?: string | null;
  version?: string | null;
  protection_kind: string;
  protector_product?: string | null;
  protector_secondary?: string | null;
  sha256?: string | null;
  file_format?: string | null;
  architecture?: string | null;
  source_uri?: string | null;
  static_analysis_authorized: boolean;
  tool_transform_authorized: boolean;
  dynamic_execution_authorized: boolean;
  material_present: boolean;
  sha256_verified: boolean;
  intake_ready: boolean;
  vulnerability_ground_truth_available: boolean;
  finding_count?: number | null;
  finding_status_counts: Record<string, number>;
  evidence_chain_complete?: boolean | null;
  static_signals_observed?: boolean | null;
  pseudocode_available?: boolean | null;
  target_executed: boolean;
  report_links: Record<string, string>;
  issues: string[];
}

export interface AcceptanceGroup {
  group_id: string;
  title: string;
  status: AcceptanceStatus;
  summary: string;
  providers: AcceptanceProviderStatus[];
  targets: AcceptanceTarget[];
  conditions: AcceptanceCondition[];
  comparison: AcceptanceProviderComparison[];
  latest_run: Record<string, any>;
}

export interface AcceptanceOverview {
  passed_groups: number;
  total_groups: number;
  status_text: string;
  code_version: string;
  benchmark_version: string;
  benchmark_summary: BenchmarkSummary;
  llm_comparison_summary: LLMComparisonSummary;
  generated_at: string;
  environment: Record<string, any>;
  notices: string[];
  groups: AcceptanceGroup[];
}

// ---- User-selected acceptance batches (separate from the fixed benchmark) ----

export type CustomAcceptanceBatchState = "configured" | "partial" | "completed";

export interface CustomAcceptanceTaskLink {
  task_id: string;
  group_id: "a" | "b" | "c" | string;
  target_id: string;
  target_path: string;
  file_name: string;
  target_type: string;
  file_format?: string | null;
  sha256?: string | null;
  model_name?: string | null;
  protection_category?: string | null;
  declared_protection?: string | null;
  observed_protection_methods: string[];
  task_status: string;
  finding_count: number;
  evidence_count: number;
  verification_count: number;
  report_available: boolean;
  report_links: Record<string, string>;
  missing: boolean;
}

export interface CustomAcceptanceGroupProgress {
  group_id: "a" | "b" | "c" | string;
  title: string;
  required_count: number;
  selected_count: number;
  completed_count: number;
  execution_complete: boolean;
  metric_status: "not_evaluated" | string;
  summary: string;
}

export interface CustomAcceptanceBatch {
  batch_id: string;
  name: string;
  state: CustomAcceptanceBatchState;
  created_at: string;
  updated_at: string;
  model_names: string[];
  model_task_ids: string[];
  packed_task_ids: string[];
  obfuscated_task_ids: string[];
  completed_groups: number;
  total_groups: number;
  groups: CustomAcceptanceGroupProgress[];
  task_links: CustomAcceptanceTaskLink[];
  metric_note: string;
}

// ---- Local three-category test laboratory ----

export type LabCategory = "local_llm" | "packed_binary" | "obfuscated_binary";
export type LabRunState = "queued" | "running" | "cancelling" | "cancelled" | "completed" | "partial" | "failed" | "blocked";

export interface LocalModelTarget {
  name: string;
  base_url: string;
  model: string;
}

export interface BinaryLabTarget {
  name: string;
  path: string;
  version?: string | null;
  protector?: string | null;
  protection_strength?: "unknown" | "none" | "compression" | "encryption" | "light_virtualization" | "code_obfuscation";
  expected_sha256?: string | null;
  authorization_confirmed: boolean;
  dynamic_validation: boolean;
  validation_inputs: string[];
  emulator_serial?: string | null;
}

export interface LabLogEntry {
  timestamp: string;
  stage: "intake" | "discovery" | "verification" | "report";
  level: "info" | "success" | "warning" | "error";
  target?: string | null;
  message: string;
}

export interface LabTargetResult {
  target_name: string;
  status: "completed" | "partial" | "failed" | "blocked";
  task_id?: string | null;
  sha256?: string | null;
  finding_count: number;
  confirmed_count: number;
  uncertain_count: number;
  evidence_count: number;
  discovery: Record<string, any>;
  verification: Record<string, any>;
  sandbox: Record<string, any>;
  report_available: boolean;
  error?: string | null;
}

export interface LabRun {
  run_id: string;
  name: string;
  category: LabCategory;
  state: LabRunState;
  created_at: string;
  updated_at: string;
  target_count: number;
  dynamic_validation_requested: boolean;
  logs: LabLogEntry[];
  results: LabTargetResult[];
  archived_task_ids: string[];
  summary: Record<string, number>;
}

export interface LabArchiveResult {
  run_id: string;
  task_ids: string[];
  finding_count: number;
  evidence_count: number;
  report_count: number;
}

// ---- Local Ollama vulnerability scanner ----

export type LLMVulnerabilityType =
  | "prompt_injection"
  | "system_prompt_leakage"
  | "safety_alignment_bypass";
export type LLMRiskLevel = "high" | "medium" | "low";
export type LLMProbeVerdict = "triggered" | "not_triggered" | "error";
export type LLMScanState = "queued" | "running" | "cancelling" | "cancelled" | "completed" | "partial" | "failed";

export interface OllamaModelOption {
  display_name: string;
  model_name: string;
  family: string;
  installed: boolean;
  service_available: boolean;
  status_text: string;
}

export interface LLMScanLogEntry {
  sequence: number;
  timestamp: string;
  level: string;
  phase: string;
  message: string;
  case_id?: string | null;
  vulnerability_type?: LLMVulnerabilityType | null;
  payload_excerpt?: string | null;
  response_excerpt?: string | null;
  verdict?: LLMProbeVerdict | null;
}

export interface LLMProbeResult {
  case_id: string;
  title: string;
  vulnerability_type: LLMVulnerabilityType;
  severity: LLMRiskLevel;
  verdict: LLMProbeVerdict;
  decision_basis: string;
  raw_request: { system: string; user: string };
  raw_response: string;
  response_sha256: string;
  matched_indicators: string[];
  elapsed_ms: number;
  prompt_tokens?: number | null;
  completion_tokens?: number | null;
  error?: string | null;
}

export interface LLMScanSummary {
  total_cases: number;
  completed_cases: number;
  triggered_count: number;
  not_triggered_count: number;
  error_count: number;
  by_severity: Record<LLMRiskLevel, number>;
  by_vulnerability_type: Record<LLMVulnerabilityType, number>;
}

export interface LLMScanProgress {
  scan_id: string;
  state: LLMScanState;
  model_name: string;
  current_case_id?: string | null;
  progress_percent: number;
  summary: LLMScanSummary;
  logs: LLMScanLogEntry[];
  error?: string | null;
  archived_task_id?: string | null;
}

export interface LLMScanResult extends LLMScanProgress {
  requested_types: LLMVulnerabilityType[];
  created_at: string;
  updated_at: string;
  results: LLMProbeResult[];
}

export interface LLMArchiveResult {
  scan_id: string;
  task_id: string;
  candidate_count: number;
  evidence_count: number;
  report_available: boolean;
}

// ---- Controlled, non-weaponized PoC evidence replay ----

export interface ControlledPocBundle {
  bundle_id: string;
  task_id: string;
  vulnerability_id: string;
  title: string;
  vulnerability_type: string;
  cwe_id?: string | null;
  target_type: string;
  target_path: string;
  target_sha256: string;
  verification_status: "confirmed" | string;
  verification_confidence: number;
  verification_rationale: string;
  evidence_ids: string[];
  code_kind: "evidence_replay" | string;
  language: "python" | string;
  filename: string;
  code: string;
  artifact_path: string;
  artifact_uri: string;
  created_at: string;
  safety_profile: {
    local_only: boolean;
    target_execution: boolean;
    network_access: boolean;
    command_execution: boolean;
    privilege_escalation: boolean;
    persistence: boolean;
    evasion: boolean;
  };
  checks: string[];
}
