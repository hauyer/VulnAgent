import {
  Task,
  Target,
  VulnerabilityCandidate,
  Evidence,
  DomainEvent,
  ReportResult,
} from "../src/types.js";

class InMemoryState {
  tasks: Map<string, Task> = new Map();
  findings: Map<string, VulnerabilityCandidate[]> = new Map();
  evidence: Map<string, Evidence[]> = new Map();
  events: Map<string, DomainEvent[]> = new Map();
  reports: Map<string, ReportResult[]> = new Map();

  constructor() {
    this.seedInitialData();
  }

  private seedInitialData() {
    const sampleTaskId = "task-demo-buffer-overflow-01";
    const target: Target = {
      target_id: "target-network-daemon-c",
      path: "samples/c_buffer_overflow/vuln_server.c",
      target_type: "source",
      language: "C",
      file_format: "C Source Code (.c)",
      metadata: {
        architecture: "x86_64",
        compiler_flags: ["-fno-stack-protector", "-z", "execstack"],
      },
    };

    const task: Task = {
      task_id: sampleTaskId,
      target,
      status: "completed",
      created_at: new Date(Date.now() - 3600000).toISOString(),
      updated_at: new Date(Date.now() - 3540000).toISOString(),
      error: null,
      metadata: {
        completed_agents: [
          "planner_agent",
          "source_audit_agent",
          "fuzz_agent",
          "verification_agent",
          "reviewer_agent",
          "report_agent",
        ],
      },
    };

    this.tasks.set(sampleTaskId, task);

    const ev1: Evidence = {
      evidence_id: "ev-c-src-01",
      task_id: sampleTaskId,
      evidence_type: "source_location",
      source: "source_audit_agent",
      description: "Unbounded strcpy() call in handle_client_request() reading into stack buffer",
      artifact_path: "samples/c_buffer_overflow/vuln_server.c:42",
      data: {
        code_snippet: `void handle_client_request(int client_sock) {\n    char req_buf[256];\n    char raw_payload[1024];\n    read(client_sock, raw_payload, sizeof(raw_payload));\n    strcpy(req_buf, raw_payload); // [!] VULNERABLE: No length boundary check\n}`,
        line_start: 40,
        line_end: 46,
      },
      reliability: 0.95,
      created_by: "SourceAuditAgent",
      created_at: new Date(Date.now() - 3580000).toISOString(),
    };

    const ev2: Evidence = {
      evidence_id: "ev-c-fuzz-01",
      task_id: sampleTaskId,
      evidence_type: "crash_log",
      source: "fuzz_agent",
      description: "AFL++ / libFuzzer crash reproducer triggered SIGSEGV at RIP 0x4141414141414141",
      artifact_path: "artifacts/crashes/crash-sigsegv-offset264.bin",
      data: {
        signal: "SIGSEGV",
        faulting_instruction: "ret (0xc3)",
        saved_rip: "0x4141414141414141",
        mutation_seed_length: 272,
        sanitizer_output: "==29341==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7ffd129a at pc 0x55d21a",
      },
      reliability: 1.0,
      created_by: "FuzzAgent",
      created_at: new Date(Date.now() - 3560000).toISOString(),
    };

    const ev3: Evidence = {
      evidence_id: "ev-c-verif-01",
      task_id: sampleTaskId,
      evidence_type: "verification_result",
      source: "verification_agent",
      description: "Independent symbolic verification confirmed control flow hijack feasibility",
      artifact_path: null,
      data: {
        exploitability_rating: "HIGH_EXPLOITABLE",
        verification_method: "Concolic taint path + Sanitizer crash re-execution",
        canary_bypassed: true,
      },
      reliability: 0.98,
      created_by: "VerificationAgent",
      created_at: new Date(Date.now() - 3550000).toISOString(),
    };

    this.evidence.set(sampleTaskId, [ev1, ev2, ev3]);

    const candidate1: VulnerabilityCandidate = {
      vulnerability_id: "vuln-cand-c-001",
      task_id: sampleTaskId,
      title: "Stack-Based Buffer Overflow in handle_client_request",
      vulnerability_type: "Stack Buffer Overflow",
      cwe_id: "CWE-120",
      description: "The application copies an untrusted network payload of up to 1024 bytes into a fixed 256-byte stack array using strcpy(). This allows a remote unauthenticated attacker to overwrite the saved return address (RIP) and hijack execution flow.",
      target_id: target.target_id,
      location: {
        file_path: "samples/c_buffer_overflow/vuln_server.c",
        function_name: "handle_client_request",
        line_start: 40,
        line_end: 46,
      },
      source_agent: "source_audit_agent",
      source_type: "source",
      producer: "SourceAuditAgent",
      confidence: 0.98,
      severity: "CRITICAL",
      evidence_ids: [ev1.evidence_id, ev2.evidence_id, ev3.evidence_id],
      status: "confirmed",
      metadata: {
        cvss_score: 9.8,
        cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      },
    };

    const candidate2: VulnerabilityCandidate = {
      vulnerability_id: "vuln-cand-c-002",
      task_id: sampleTaskId,
      title: "Potential Integer Truncation on Header Length",
      vulnerability_type: "Integer Overflow",
      cwe_id: "CWE-190",
      description: "Header length cast to unsigned short before comparison with packet size buffer.",
      target_id: target.target_id,
      location: {
        file_path: "samples/c_buffer_overflow/vuln_server.c",
        function_name: "parse_header",
        line_start: 22,
        line_end: 26,
      },
      source_agent: "source_audit_agent",
      source_type: "source",
      producer: "SourceAuditAgent",
      confidence: 0.45,
      severity: "LOW",
      evidence_ids: [ev1.evidence_id],
      status: "uncertain",
      metadata: {
        note: "Requires complex heap layout to trigger out-of-bounds read; secondary review queued.",
      },
    };

    this.findings.set(sampleTaskId, [candidate1, candidate2]);

    const events: DomainEvent[] = [
      {
        event_id: "evt-01",
        task_id: sampleTaskId,
        event_type: "task_started",
        payload: { target_type: "source", path: target.path },
        timestamp: new Date(Date.now() - 3600000).toISOString(),
      },
      {
        event_id: "evt-02",
        task_id: sampleTaskId,
        event_type: "agent_routed",
        payload: { route: "planner_agent", description: "Analyzing target attack surface" },
        timestamp: new Date(Date.now() - 3590000).toISOString(),
      },
      {
        event_id: "evt-03",
        task_id: sampleTaskId,
        event_type: "agent_started",
        payload: { route: "planner_agent" },
        timestamp: new Date(Date.now() - 3589000).toISOString(),
      },
      {
        event_id: "evt-04",
        task_id: sampleTaskId,
        event_type: "candidate_created",
        payload: { vulnerability_id: candidate1.vulnerability_id, cwe_id: "CWE-120" },
        timestamp: new Date(Date.now() - 3580000).toISOString(),
      },
      {
        event_id: "evt-05",
        task_id: sampleTaskId,
        event_type: "evidence_added",
        payload: { evidence_id: ev1.evidence_id, type: ev1.evidence_type },
        timestamp: new Date(Date.now() - 3580000).toISOString(),
      },
      {
        event_id: "evt-06",
        task_id: sampleTaskId,
        event_type: "agent_routed",
        payload: { route: "fuzz_agent", description: "Dynamic verification with AFL++" },
        timestamp: new Date(Date.now() - 3570000).toISOString(),
      },
      {
        event_id: "evt-07",
        task_id: sampleTaskId,
        event_type: "evidence_added",
        payload: { evidence_id: ev2.evidence_id, type: ev2.evidence_type },
        timestamp: new Date(Date.now() - 3560000).toISOString(),
      },
      {
        event_id: "evt-08",
        task_id: sampleTaskId,
        event_type: "verification_started",
        payload: { vulnerability_id: candidate1.vulnerability_id },
        timestamp: new Date(Date.now() - 3555000).toISOString(),
      },
      {
        event_id: "evt-09",
        task_id: sampleTaskId,
        event_type: "candidate_confirmed",
        payload: { vulnerability_id: candidate1.vulnerability_id, confidence: 0.98 },
        timestamp: new Date(Date.now() - 3550000).toISOString(),
      },
      {
        event_id: "evt-10",
        task_id: sampleTaskId,
        event_type: "evidence_added",
        payload: { evidence_id: ev3.evidence_id, type: ev3.evidence_type },
        timestamp: new Date(Date.now() - 3550000).toISOString(),
      },
      {
        event_id: "evt-11",
        task_id: sampleTaskId,
        event_type: "review_completed",
        payload: { status: "approved" },
        timestamp: new Date(Date.now() - 3545000).toISOString(),
      },
      {
        event_id: "evt-12",
        task_id: sampleTaskId,
        event_type: "report_generated",
        payload: { report_id: "rep-" + sampleTaskId },
        timestamp: new Date(Date.now() - 3540000).toISOString(),
      },
      {
        event_id: "evt-13",
        task_id: sampleTaskId,
        event_type: "task_completed",
        payload: { status: "completed" },
        timestamp: new Date(Date.now() - 3540000).toISOString(),
      },
    ];

    this.events.set(sampleTaskId, events);

    const report: ReportResult = {
      task_id: sampleTaskId,
      content: {
        summary: "VulnAgent Multi-Agent Security Audit completed with 1 Critical confirmed vulnerability.",
        executive_summary: "A severe stack buffer overflow vulnerability was identified in handle_client_request(). Static AST taint analysis correlated with dynamic fuzz crash dumps confirms that unauthenticated remote code execution is possible.",
        target_info: {
          path: target.path,
          type: target.target_type,
          language: target.language,
        },
        metrics: {
          total_candidates: 2,
          confirmed_vulnerabilities: 1,
          rejected_false_positives: 0,
          uncertain_findings: 1,
          evidence_count: 3,
        },
        severity_breakdown: {
          critical: 1,
          high: 0,
          medium: 0,
          low: 1,
        },
        findings: [candidate1, candidate2],
        recommendations: [
          "Replace unsafe strcpy() with bounded string operations such as strlcpy() or snprintf().",
          "Enable compiler hardening flags: -fstack-protector-strong, -D_FORTIFY_SOURCE=2, and ASLR/PIE.",
          "Implement strict input length validation prior to parsing packet buffers.",
        ],
      },
      artifact_uri: "/artifacts/reports/report-" + sampleTaskId + ".json",
      metadata: {
        generated_by: "ReportAgent",
        version: "0.2.0",
      },
    };

    this.reports.set(sampleTaskId, [report]);
  }
}

export const db = new InMemoryState();
