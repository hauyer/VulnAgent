"""Unit tests for the V0.5 candidate fusion engine (P4).

Two engines rediscovering the same flaw must collapse into one FusedCandidate;
nearby locations, path separators and missing CWE components must not split or
over-merge findings.
"""

from vulnagent.analyzers.source.fusion import CandidateFusionEngine, CandidateNormalizer
from vulnagent.contracts import (
    VulnerabilityCandidate,
    VulnerabilityLocation,
    VulnerabilityStatus,
)

TASK_ID = "task-1"


def make_candidate(
    vulnerability_id: str,
    *,
    cwe_id: str | None = "CWE-78",
    vulnerability_type: str = "command_injection",
    file_path: str = "src/app.py",
    line: int = 2,
    function: str = "parse",
    sink: str | None = "os.system",
    sources: list[str] | None = None,
    producer: str = "native",
    confidence: float = 0.7,
    evidence_ids: list[str] | None = None,
) -> VulnerabilityCandidate:
    return VulnerabilityCandidate(
        vulnerability_id=vulnerability_id,
        task_id=TASK_ID,
        title="Potential command injection",
        vulnerability_type=vulnerability_type,
        cwe_id=cwe_id,
        description="User input may reach an unsafe sink.",
        target_id="target-1",
        location=VulnerabilityLocation(
            file_path=file_path,
            function_name=function,
            line_start=line,
            line_end=line,
            module_name="app",
        ),
        source_agent="source_audit",
        source_type="source",
        producer=producer,
        confidence=confidence,
        severity="HIGH",
        evidence_ids=evidence_ids or [],
        metadata={
            "sink": sink,
            "source_kinds": sources or ["input"],
            "rule_id": f"rule-{vulnerability_id}",
            "analysis_engine": producer,
        },
    )


def test_normalizer_fingerprints_native_and_semgrep_same_flaw() -> None:
    normalizer = CandidateNormalizer()
    native = make_candidate("n1", producer="native")
    semgrep = make_candidate("s1", producer="semgrep", cwe_id="CWE-78", confidence=0.6)
    fp_native = normalizer.fingerprint(native)
    fp_semgrep = normalizer.fingerprint(semgrep)
    assert fp_native.key == fp_semgrep.key
    assert fp_native.cwe_id == "CWE-78"
    assert fp_native.sink == "os.system"
    assert fp_native.taint_source == "input"
    assert fp_native.normalized_location == "src/app.py@0"


def test_path_separator_and_prefix_are_normalized() -> None:
    normalizer = CandidateNormalizer()
    a = make_candidate("n1", file_path=r"src\app.py", line=2)
    b = make_candidate("n2", file_path="src/app.py", line=2)
    assert normalizer.fingerprint(a).key == normalizer.fingerprint(b).key


def test_lines_within_tolerance_share_bucket() -> None:
    normalizer = CandidateNormalizer()
    a = make_candidate("n1", line=2)
    b = make_candidate("n2", line=3)
    assert normalizer.fingerprint(a).normalized_location == "src/app.py@0"
    assert normalizer.fingerprint(b).normalized_location == "src/app.py@0"
    assert normalizer.fingerprint(a).key == normalizer.fingerprint(b).key


def test_missing_cwe_falls_back_to_vulnerability_type() -> None:
    # Candidates without a CWE id fingerprint via their vulnerability type, so
    # engine peers that both omit CWE still fuse; a different type splits.
    normalizer = CandidateNormalizer()
    a = make_candidate("n1", cwe_id=None)
    b = make_candidate("n2", cwe_id=None)
    c = make_candidate("n3", cwe_id=None, vulnerability_type="code_injection")
    assert normalizer.fingerprint(a).key == normalizer.fingerprint(b).key
    assert normalizer.fingerprint(a).key != normalizer.fingerprint(c).key


def test_different_sink_produces_different_fingerprint() -> None:
    normalizer = CandidateNormalizer()
    a = make_candidate("n1", sink="os.system")
    b = make_candidate("n2", sink="subprocess.Popen")
    assert normalizer.fingerprint(a).key != normalizer.fingerprint(b).key


def test_fuse_collapses_same_flaw_from_two_engines() -> None:
    engine = CandidateFusionEngine()
    candidates = [
        make_candidate("n1", producer="native", confidence=0.8, evidence_ids=["ev-native"]),
        make_candidate("s1", producer="semgrep", confidence=0.6, evidence_ids=["ev-semgrep"]),
    ]
    fused = engine.fuse(
        candidates,
        independence_groups={"n1": "native-taint", "s1": "semgrep"},
    )
    assert len(fused) == 1
    item = fused[0]
    assert item.source_candidates == ["s1", "n1"] or set(item.source_candidates) == {"n1", "s1"}
    assert item.supporting_independence_groups == ["native-taint", "semgrep"]
    assert set(item.evidence_ids) == {"ev-native", "ev-semgrep"}
    assert item.fused_confidence == 0.8
    assert item.status is VulnerabilityStatus.CANDIDATE
    assert item.metadata["member_count"] == 2
    assert item.metadata["member_producers"] == ["native", "semgrep"]


def test_fuse_matches_across_missing_function_and_taint_source() -> None:
    # Real cross-engine divergence: native resolves function/taint source,
    # semgrep does not.  Same CWE + location + sink must still fuse (loose key).
    engine = CandidateFusionEngine()
    native = make_candidate(
        "n1", producer="native", cwe_id="CWE-78", sink="subprocess.run",
        function="parse", sources=["input"], confidence=0.84,
    )
    semgrep = make_candidate(
        "s1", producer="semgrep", cwe_id="CWE-78", sink="subprocess.run",
        function=None, sources=None, confidence=0.6,
    )
    fused = engine.fuse(
        [native, semgrep],
        independence_groups={"n1": "native-taint", "s1": "semgrep"},
    )
    assert len(fused) == 1
    item = fused[0]
    assert set(item.source_candidates) == {"n1", "s1"}
    assert item.supporting_independence_groups == ["native-taint", "semgrep"]
    assert len(item.metadata["strict_keys"]) == 2


def test_fuse_separates_distinct_flaws() -> None:
    engine = CandidateFusionEngine()
    candidates = [
        make_candidate("n1", sink="os.system"),
        make_candidate("n2", sink="eval", vulnerability_type="code_injection", cwe_id="CWE-95"),
    ]
    fused = engine.fuse(candidates)
    assert len(fused) == 2


def test_fuse_wraps_single_candidate() -> None:
    engine = CandidateFusionEngine()
    candidates = [make_candidate("n1", producer="native")]
    fused = engine.fuse(candidates)
    assert len(fused) == 1
    assert fused[0].source_candidates == ["n1"]
    assert fused[0].supporting_independence_groups == []
    assert fused[0].fused_confidence == 0.7


def test_fuse_dedups_independence_groups() -> None:
    engine = CandidateFusionEngine()
    candidates = [
        make_candidate("n1", producer="native"),
        make_candidate("n2", producer="native-2"),
        make_candidate("s1", producer="semgrep"),
    ]
    fused = engine.fuse(
        candidates,
        independence_groups={"n1": "native-taint", "n2": "native-taint", "s1": "semgrep"},
    )
    assert len(fused) == 1
    assert fused[0].supporting_independence_groups == ["native-taint", "semgrep"]
    assert fused[0].metadata["member_count"] == 3


def test_fuse_sorts_by_confidence_descending() -> None:
    engine = CandidateFusionEngine()
    candidates = [
        make_candidate("low", sink="a", confidence=0.3),
        make_candidate("high", sink="b", confidence=0.9),
        make_candidate("mid", sink="c", confidence=0.6),
    ]
    fused = engine.fuse(candidates)
    assert [item.fused_confidence for item in fused] == [0.9, 0.6, 0.3]


def test_fuse_normalizes_absolute_vs_relative_paths(tmp_path) -> None:
    # One engine reports the absolute path, another the project-relative path;
    # with base_path given, both must land on the same location identity.
    target_root = tmp_path / "target"
    target_root.mkdir()
    (target_root / "app.py").write_text("print(1)\n")
    engine = CandidateFusionEngine()
    absolute = make_candidate("n1", file_path=str(target_root / "app.py"))
    relative = make_candidate("s1", file_path="app.py")
    fused = engine.fuse([absolute, relative], base_path=str(target_root))
    assert len(fused) == 1
    assert set(fused[0].source_candidates) == {"n1", "s1"}
