# Build the p1c-microtar-exploration archive: candidates.jsonl + evidence.jsonl
# using the frozen contracts models (VulnerabilityCandidate / Evidence).
import json, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))  # repo root
from vulnagent.contracts.vulnerability import VulnerabilityCandidate, VulnerabilityLocation, VulnerabilityStatus
from vulnagent.contracts.evidence import Evidence, EvidenceType

TASK = "p1c-microtar-exploration"
TARGET = "microtar@27076e1"
ROOT = Path(r"D:\课程设计小学期\VulnAgent\artifacts\experiments\p1c-microtar-exploration")
ROOT.mkdir(parents=True, exist_ok=True)

evidences = [
    Evidence(
        evidence_id="ev-mt-001",
        task_id=TASK,
        evidence_type=EvidenceType.CRASH_LOG,
        source="ASan stack-buffer-overflow READ of size 366 via sscanf(rh->checksum) in raw_to_header (mtar_read_header L100)",
        description="Trigger seed A (non-NUL 100-byte name, valid checksum, non-NUL checksum field): UCRT sscanf performs strnlen over the non-NUL-terminated 8-byte checksum field and reads 366 bytes past the stack record. Reproduced twice, exit=1.",
        artifact_path="src/crash_report_1.txt",
        data={"seed": "seed_nonnull_name_validchk.tar", "asan_read_size": 366, "replay_runs": 2, "stack": ["__stdio_common_vsscanf", "sscanf", "raw_to_header", "mtar_read_header"]},
        reliability=0.98,
        created_by="BlindDiscoveryRunner(p1c)",
    ),
    Evidence(
        evidence_id="ev-mt-002",
        task_id=TASK,
        evidence_type=EvidenceType.CRASH_LOG,
        source="ASan stack-buffer-overflow READ of size 357 via strcpy(h->name, rh->name) in raw_to_header (mtar_read_header L112)",
        description="Trigger seed B (non-NUL name, checksum[7]=NUL): strcpy reads 357 bytes past the 100-byte name field until the checksum NUL. Matches public CVE-2026-55738/CVE-2026-43623 description ('READ of size 356'). Reproduced, exit=1.",
        artifact_path="src/crash_report_strcpy.txt",
        data={"seed": "seed_strcpy_write_chk_nul.tar", "asan_read_size": 357, "replay_runs": 1, "cve_match": "CVE-2026-55738 / CVE-2026-43623"},
        reliability=0.98,
        created_by="BlindDiscoveryRunner(p1c)",
    ),
    Evidence(
        evidence_id="ev-mt-003",
        task_id=TASK,
        evidence_type=EvidenceType.TOOL_RESULT,
        source="Dedup search (general_search): public records for microtar 0.1.0",
        description="Post-run record-side search found CVE-2026-55738 (raw_to_header strcpy stack overflow, Red Hat bug 2489845), CVE-2026-43623 (same, VulnCheck), CVE-2026-54417 (mtar_next integer overflow), CVE-2026-71267 (write-path long filename). Our triggers reproduce the same defect family => duplicate, not novel.",
        artifact_path="",
        data={"cves": ["CVE-2026-55738", "CVE-2026-43623", "CVE-2026-54417", "CVE-2026-71267"], "novelty_status": "likely_duplicate", "published": "2026-06..08"},
        reliability=0.95,
        created_by="ResearchRecord(p1c)",
    ),
    Evidence(
        evidence_id="ev-mt-004",
        task_id=TASK,
        evidence_type=EvidenceType.SOURCE_LOCATION,
        source="raw_to_header() src/microtar.c L90-114 (sscanf x6 + strcpy x2 without NUL-termination checks)",
        description="POSIX ustar allows fixed-width fields fully populated with non-NUL bytes; microtar parses them with sscanf/strcpy on non-NUL-terminated stack buffers => OOB read; strcpy also over-writes the 100-byte destination.",
        artifact_path="third_party/microtar/src/microtar.c",
        data={"functions": ["raw_to_header"], "lines": [90, 114], "cwe": "CWE-121"},
        reliability=0.97,
        created_by="Reviewer(p1c)",
    ),
]

candidate = VulnerabilityCandidate(
    vulnerability_id="vuln-mt-0001",
    task_id=TASK,
    title="microtar 0.1.0 raw_to_header: missing NUL-termination handling on fixed-width TAR header fields causes stack OOB read (and strcpy write overflow)",
    vulnerability_type="Stack buffer over-read (and over-write via strcpy)",
    cwe_id="CWE-121",
    description="Crafted TAR header whose name/checksum fields are fully populated with non-NUL bytes makes sscanf/strcpy in raw_to_header read past the stack record (ASan READ of size 366 via sscanf, READ of size 357 via strcpy). Duplicate of public CVE-2026-55738 / CVE-2026-43623 (same defect, independently re-discovered blind). DoS / info-leak class; not claimed as novel.",
    target_id=TARGET,
    location=VulnerabilityLocation(file_path="src/microtar.c", function_name="raw_to_header", line_start=90, line_end=114),
    source_agent="BlindDiscoveryRunner(p1c)",
    source_type="dynamic_fuzz",
    producer="libFuzzer+ASan",
    confidence=0.95,
    severity="medium",
    evidence_ids=["ev-mt-001", "ev-mt-002", "ev-mt-003", "ev-mt-004"],
    status=VulnerabilityStatus.VERIFYING,
    metadata={"novelty_status": "likely_duplicate", "public_cves": ["CVE-2026-55738", "CVE-2026-43623"], "practice_mode": False, "run_status": "reproduced", "disclosure": "not_submitted_duplicate"},
)

with open(ROOT / "candidates.jsonl", "w", encoding="utf-8") as f:
    f.write(candidate.model_dump_json() + "\n")
with open(ROOT / "evidence.jsonl", "w", encoding="utf-8") as f:
    for e in evidences:
        f.write(e.model_dump_json() + "\n")
print("candidates:", 1, "evidence:", len(evidences))
