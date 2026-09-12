"""Static binary analysis agent; target binaries are never executed."""

import asyncio
import re
from collections.abc import Mapping
from typing import Any, Protocol

from vulnagent.agents.base import BaseAgent
from vulnagent.contracts import (
    AgentMessage,
    AgentMessageType,
    AgentResult,
    AnalysisContext,
    BinaryAnalysisRequest,
    BinaryAnalysisResult,
    BinaryAnalyzer,
    BinaryFeatureAnalyzer,
    Evidence,
    EvidenceType,
    Task,
    VulnerabilityCandidate,
    VulnerabilityLocation,
)
from vulnagent.utils.ids import new_evidence_id, new_message_id, new_vulnerability_id


RISKY_SYMBOLS = frozenset(
    {"gets", "strcpy", "strcat", "sprintf", "vsprintf", "system", "popen", "scanf"}
)
_SYMBOL_TOKEN = re.compile(r"[a-z0-9_@?]+")
_KNOWN_SYMBOL_PREFIXES = ("__imp_", "_imp__", "ucrt_")


class AuthorizedBinaryWorkflow(Protocol):
    """Private port for authorization-gated reverse-analysis orchestration."""

    async def analyze(
        self,
        request: BinaryAnalysisRequest,
        *,
        authorized: bool = False,
        unpack: bool = False,
        auto_unpack: bool = False,
    ) -> Any: ...


class BinaryAnalysisAgent(BaseAgent):
    """Coordinate a bounded static analyzer and normalize concrete signals."""

    name = "binary_analysis"

    def __init__(
        self,
        analyzer: BinaryAnalyzer,
        logic_analyzer: BinaryFeatureAnalyzer | None = None,
        obfuscation_analyzer: BinaryFeatureAnalyzer | None = None,
        reverse_workflow: AuthorizedBinaryWorkflow | None = None,
    ) -> None:
        self.analyzer = analyzer
        self.logic_analyzer = logic_analyzer
        self.obfuscation_analyzer = obfuscation_analyzer
        self.reverse_workflow = reverse_workflow

    async def run(self, task: Task, context: AnalysisContext) -> AgentResult:
        analysis_path = self._restored_input_path(context) or task.target.path
        request = BinaryAnalysisRequest(
            task_id=task.task_id,
            target_id=task.target.target_id,
            path=analysis_path,
        )
        analysis = await self._analyze(task, request)
        target_metadata = (
            task.target.metadata if isinstance(task.target.metadata, Mapping) else {}
        )
        # Keep user/manifest attribution separate from analyzer observations.  The
        # frontend can therefore say "declared" without presenting free text as
        # a detector verdict.
        analysis.metadata.setdefault(
            "declared_protection", target_metadata.get("protection")
        )
        analysis.metadata.setdefault(
            "protection_category", target_metadata.get("test_lab_category")
        )
        analysis.metadata.setdefault("original_target_path", task.target.path)
        analysis.metadata.setdefault("restored_input_selected", analysis_path != task.target.path)
        logic_input = self._logic_input(analysis)
        logic, obfuscation = await asyncio.gather(
            self._inspect_feature(self.logic_analyzer, logic_input, "binary.logic"),
            self._inspect_feature(
                self.obfuscation_analyzer,
                analysis,
                "binary.obfuscation",
            ),
        )
        self._complete_analysis_plan(analysis)
        is_mock = bool(analysis.metadata.get("mock"))
        reverse_view = self._reverse_view(analysis)
        pseudocode = reverse_view["pseudocode"]
        explicit_matches = self._risky_symbols(analysis.imports, analysis.strings)
        pseudocode_matches = self._risky_symbols(
            [],
            list(pseudocode.values()),
            allow_embedded_text=True,
        )
        matched = sorted(set(explicit_matches).union(pseudocode_matches))
        semantic_callsites = self._risky_callsites(analysis.metadata)
        matched = sorted(
            set(matched).union(
                str(item["inferred_api"])
                for item in semantic_callsites
                if item.get("inferred_api")
            )
        )
        evidence = self._feature_evidence(task.task_id, analysis, logic, obfuscation)
        findings: list[VulnerabilityCandidate] = []

        if is_mock:
            matched = ["mock-signal"]

        if matched:
            semantic_only = bool(semantic_callsites)
            pseudocode_hit = bool(pseudocode_matches)
            pseudocode_location = self._first_pseudocode_match(
                pseudocode,
                matched,
                reverse_view["functions"],
            )
            binary_locator = self._binary_locator(
                analysis,
                pseudocode_location,
                semantic_callsites,
                matched,
                reverse_view["functions"],
            )
            signal_basis = (
                "pe_x64_callsite_semantics"
                if semantic_only
                else "decompiled_pseudocode"
                if pseudocode_hit
                else "explicit_symbol"
            )
            signal = Evidence(
                evidence_id=new_evidence_id(),
                task_id=task.task_id,
                evidence_type=(
                    EvidenceType.DISASSEMBLY
                    if (semantic_only or pseudocode_hit) and not is_mock
                    else EvidenceType.BINARY_ADDRESS
                ),
                source=self.name,
                description=(
                    "Synthetic binary location from the mock analyzer."
                    if is_mock
                    else (
                        "Bounded call-site decoding inferred an unbounded format write "
                        "from the runtime helper argument shape."
                        if semantic_only
                        else "Decompiled pseudocode contains a recognized risky API call."
                        if pseudocode_hit
                        else "Static binary inspection located a risky imported or embedded symbol."
                    )
                ),
                data={
                    "path": analysis.path,
                    "file_format": analysis.file_format,
                    "architecture": analysis.architecture,
                    "matched_symbols": matched,
                    "semantic_callsites": semantic_callsites,
                    "signal_basis": signal_basis,
                    "code_snippet": pseudocode_location.get("code_snippet"),
                    "pseudocode_address": binary_locator.get("binary_address"),
                    "function": binary_locator.get("function_name"),
                    "module_name": analysis.path,
                    "locator_kind": binary_locator["locator_kind"],
                    "locator_precision": binary_locator["locator_precision"],
                    "located_symbol": binary_locator.get("located_symbol"),
                    "binary_file_offset": binary_locator.get("binary_file_offset"),
                    "sha256": analysis.metadata.get("sha256"),
                    "executed": False,
                    "mock": is_mock,
                },
                reliability=(
                    0.4
                    if is_mock
                    else 0.85
                    if semantic_only
                    else 0.8
                    if pseudocode_hit
                    else 0.75
                ),
                created_by=self.name,
            )
            evidence.append(signal)
            finding = VulnerabilityCandidate(
                vulnerability_id=new_vulnerability_id(),
                task_id=task.task_id,
                title=(
                    "Mock suspicious binary pattern"
                    if is_mock
                    else "Risky API symbol present in binary"
                ),
                vulnerability_type=(
                    "mock_binary_finding" if is_mock else "risky_binary_api"
                ),
                description=(
                    "Synthetic V0.2 binary finding; the target was not opened or executed."
                    if is_mock
                    else (
                        "A bounded static inspection inferred an unbounded format-write "
                        "wrapper from a call-site argument sentinel. This local signal "
                        "does not prove reachability or exploitability and requires verification."
                        if semantic_only
                        else "A decompiled pseudocode excerpt contains a recognized risky API call. "
                        "The excerpt and control-flow facts require independent verification."
                        if pseudocode_hit
                        else "A bounded static inspection found a risky API symbol. "
                        "This signal alone does not prove reachability and requires verification."
                    )
                ),
                target_id=task.target.target_id,
                location=VulnerabilityLocation(
                    module_name=task.target.path,
                    function_name=binary_locator.get("function_name"),
                    binary_address=binary_locator.get("binary_address"),
                ),
                source_agent=self.name,
                source_type="binary",
                producer=type(self.analyzer).__name__,
                confidence=(
                    0.4
                    if is_mock
                    else 0.72
                    if semantic_only
                    else 0.7
                    if pseudocode_hit
                    else 0.65
                ),
                severity="INFO" if is_mock else "MEDIUM",
                evidence_ids=[signal.evidence_id],
                metadata={
                    "mock": is_mock,
                    "executed": False,
                    "matched_symbols": matched,
                    "semantic_callsite_count": len(semantic_callsites),
                    "signal_basis": signal_basis,
                    "locator_kind": binary_locator["locator_kind"],
                    "locator_precision": binary_locator["locator_precision"],
                    "located_symbol": binary_locator.get("located_symbol"),
                    "binary_file_offset": binary_locator.get("binary_file_offset"),
                    "logic_categories": sorted(logic.get("summary", {})),
                    "obfuscation_score": obfuscation.get("score", 0),
                },
            )
            finding.evidence_ids.extend(
                item.evidence_id for item in evidence if item.evidence_id != signal.evidence_id
            )
            findings.append(finding)

        message = AgentMessage(
            message_id=new_message_id(),
            task_id=task.task_id,
            sender=self.name,
            receiver="verification",
            message_type=(
                AgentMessageType.VULNERABILITY_CANDIDATE
                if findings
                else AgentMessageType.ANALYSIS_RESULT
            ),
            payload={
                "finding_ids": [item.vulnerability_id for item in findings],
                "analysis": analysis.model_dump(mode="json"),
                "feature_analysis": {
                    "logic": logic,
                    "obfuscation": obfuscation,
                },
                "mock": is_mock,
            },
            evidence_ids=[item.evidence_id for item in evidence],
        )
        return AgentResult(
            agent_name=self.name,
            messages=[message],
            findings=findings,
            evidence=evidence,
        )

    @staticmethod
    def _restored_input_path(context: AnalysisContext) -> str | None:
        """Select only a parseability-validated artifact from the restoration agent."""

        for item in reversed(context.evidence):
            if item.source != "program_restoration":
                continue
            output_path = item.data.get("output_path")
            validation = item.data.get("validation")
            if (
                isinstance(output_path, str)
                and output_path
                and isinstance(validation, Mapping)
                and validation.get("parseable") is True
                and item.data.get("success") is True
            ):
                return output_path
        return None

    async def _analyze(
        self,
        task: Task,
        request: BinaryAnalysisRequest,
    ) -> BinaryAnalysisResult:
        """Select an authorization-gated reverse plan or the static baseline."""

        metadata = task.target.metadata if isinstance(task.target.metadata, Mapping) else {}
        authorized = metadata.get("authorization_confirmed") is True
        category = str(metadata.get("test_lab_category", "")).casefold()
        reverse_enabled = metadata.get("reverse_analysis_enabled") is True
        eligible = category in {"packed_binary", "obfuscated_binary"} or reverse_enabled
        if self.reverse_workflow is not None and authorized and eligible:
            try:
                return await self.reverse_workflow.analyze(
                    request,
                    authorized=True,
                    # The workflow's auto-unpack rule is deliberately narrow:
                    # even a generic custom binary is transformed only after
                    # the structural parser observes an explicit UPX marker.
                    auto_unpack=category == "packed_binary" or reverse_enabled,
                )
            except Exception as exc:  # keep the structural baseline available
                result = await self.analyzer.analyze(request)
                result.metadata["analysis_plan"] = self._baseline_plan(
                    authorized=authorized,
                    reason="reverse workflow failed; structural baseline retained",
                    reverse_status="error",
                    error_type=type(exc).__name__,
                )
                return result

        result = await self.analyzer.analyze(request)
        reason = (
            "explicit authorization is required"
            if not authorized
            else "target was not created by the packed/obfuscated laboratory"
            if not eligible
            else "reverse workflow is not configured"
        )
        result.metadata.setdefault(
            "analysis_plan",
            self._baseline_plan(
                authorized=authorized,
                reason=reason,
                reverse_status=(
                    "not_authorized"
                    if not authorized
                    else "not_required"
                    if not eligible
                    else "not_configured"
                ),
            ),
        )
        return result

    @staticmethod
    def _baseline_plan(
        *,
        authorized: bool,
        reason: str,
        reverse_status: str,
        error_type: str | None = None,
    ) -> dict[str, Any]:
        decisions: dict[str, Any] = {
            "authorization_confirmed": authorized,
            "reverse_workflow_selected": False,
            "reason": reason,
        }
        if error_type:
            decisions["error_type"] = error_type
        return {
            "version": 1,
            "planner": "binary-analysis-agent",
            "authorization_confirmed": authorized,
            "target_executed": False,
            "decisions": decisions,
            "steps": [
                {"stage": "structural_parse", "status": "completed"},
                {"stage": "unpack", "status": reverse_status},
                {"stage": "decompile", "status": reverse_status},
                {"stage": "semantic_logic", "status": "scheduled"},
                {"stage": "vulnerability_rules", "status": "scheduled"},
                {"stage": "independent_verification", "status": "scheduled"},
            ],
        }

    @staticmethod
    def _complete_analysis_plan(analysis: BinaryAnalysisResult) -> None:
        plan = analysis.metadata.get("analysis_plan")
        steps = plan.get("steps") if isinstance(plan, Mapping) else None
        if not isinstance(steps, list):
            return
        for item in steps:
            if (
                isinstance(item, dict)
                and item.get("stage") in {"semantic_logic", "vulnerability_rules"}
            ):
                item["status"] = "completed"

    @staticmethod
    def _logic_input(analysis: BinaryAnalysisResult) -> BinaryAnalysisResult:
        """Use the unpacked address space for semantic analysis when present."""

        derived = analysis.metadata.get("unpacked_analysis")
        if not isinstance(derived, Mapping):
            return analysis
        try:
            return BinaryAnalysisResult.model_validate(dict(derived))
        except Exception:
            return analysis

    @staticmethod
    def _reverse_view(analysis: BinaryAnalysisResult) -> dict[str, Any]:
        """Normalize original and unpacked reverse facts for evidence/UI use."""

        derived = analysis.metadata.get("unpacked_analysis")
        selected: Mapping[str, Any] | BinaryAnalysisResult = (
            derived if isinstance(derived, Mapping) else analysis
        )
        if isinstance(selected, BinaryAnalysisResult):
            functions = selected.functions
            cfg = selected.cfg
            metadata = selected.metadata
        else:
            functions = selected.get("functions", [])
            cfg = selected.get("cfg", {})
            metadata = selected.get("metadata", {})
        reverse_tool = metadata.get("reverse_tool") if isinstance(metadata, Mapping) else {}
        if not isinstance(reverse_tool, Mapping):
            reverse_tool = {}
        pseudocode = reverse_tool.get("pseudocode", {})
        return {
            "functions": [dict(item) for item in functions if isinstance(item, Mapping)]
            if isinstance(functions, list)
            else [],
            "cfg": {
                str(key): [str(value) for value in values]
                for key, values in cfg.items()
                if isinstance(values, list)
            }
            if isinstance(cfg, Mapping)
            else {},
            "pseudocode": {
                str(key): str(value)
                for key, value in pseudocode.items()
                if isinstance(value, str)
            }
            if isinstance(pseudocode, Mapping)
            else {},
            "reverse_tool": dict(reverse_tool),
            "derived_from_unpack": isinstance(derived, Mapping),
        }

    @staticmethod
    async def _inspect_feature(
        analyzer: BinaryFeatureAnalyzer | None,
        analysis: Any,
        capability: str,
    ) -> dict[str, Any]:
        """Run one optional feature analyzer with a public, bounded failure result."""
        if analyzer is None:
            return {"available": False, "capability": capability}
        try:
            result = await analyzer.inspect(analysis)
        except Exception as exc:  # feature failure must not discard reverse facts
            return {
                "available": True,
                "capability": capability,
                "error_type": type(exc).__name__,
            }
        return {"available": True, "capability": capability, **result}

    @classmethod
    def _feature_evidence(
        cls,
        task_id: str,
        analysis: BinaryAnalysisResult,
        logic: dict[str, Any],
        obfuscation: dict[str, Any],
    ) -> list[Evidence]:
        """Create the reverse workbench's bounded, traceable evidence model."""

        evidence: list[Evidence] = []
        reverse = cls._reverse_view(analysis)
        plan = analysis.metadata.get("analysis_plan", {})
        runs = analysis.metadata.get("tool_runs", [])
        workflow = analysis.metadata.get("workflow", {})
        packing = analysis.metadata.get("packing_signals", {})
        declared_protection = analysis.metadata.get("declared_protection")
        protection_category = analysis.metadata.get("protection_category")
        observed_methods = cls._observed_protection_methods(
            packing,
            obfuscation.get("signals"),
            derived_from_unpack=(
                reverse["derived_from_unpack"]
                or (
                    isinstance(workflow, Mapping)
                    and workflow.get("unpacked_artifact_created") is True
                )
            ),
        )
        if isinstance(plan, Mapping) or isinstance(runs, list):
            evidence.append(
                Evidence(
                    evidence_id=new_evidence_id(),
                    task_id=task_id,
                    evidence_type=EvidenceType.TOOL_RESULT,
                    source="binary_reverse",
                    description=(
                        "Authorization-gated reverse-analysis plan and offline tool "
                        "outcomes. The target image was inspected but never executed."
                    ),
                    data={
                        "file_format": analysis.file_format,
                        "architecture": analysis.architecture,
                        "sha256": analysis.metadata.get("sha256"),
                        "protection_category": protection_category,
                        "declared_protection": declared_protection,
                        "observed_protection_methods": observed_methods,
                        "packing_signals": packing if isinstance(packing, Mapping) else {},
                        "analysis_plan": dict(plan) if isinstance(plan, Mapping) else {},
                        "workflow": dict(workflow) if isinstance(workflow, Mapping) else {},
                        "tool_runs": cls._tool_run_summaries(runs),
                        "function_count": len(reverse["functions"]),
                        "pseudocode_count": len(reverse["pseudocode"]),
                        "cfg_node_count": len(reverse["cfg"]),
                        "derived_from_unpack": reverse["derived_from_unpack"],
                        "target_executed": False,
                    },
                    reliability=0.9,
                    created_by="binary_analysis",
                )
            )

        if reverse["pseudocode"]:
            evidence.append(
                Evidence(
                    evidence_id=new_evidence_id(),
                    task_id=task_id,
                    evidence_type=EvidenceType.DISASSEMBLY,
                    source="binary_reverse",
                    description=(
                        "Readable pseudocode generated by the configured offline "
                        "reverse tool for human review and downstream rules."
                    ),
                    data={
                        "source": reverse["reverse_tool"].get("source", "offline reverse tool"),
                        "functions": reverse["functions"],
                        "pseudocode": reverse["pseudocode"],
                        "derived_from_unpack": reverse["derived_from_unpack"],
                        "target_executed": False,
                    },
                    reliability=0.75,
                    created_by="binary_analysis",
                )
            )

        if reverse["cfg"]:
            evidence.append(
                Evidence(
                    evidence_id=new_evidence_id(),
                    task_id=task_id,
                    evidence_type=EvidenceType.CFG_PATH,
                    source="binary_reverse",
                    description="Normalized control-flow edges extracted without executing the target.",
                    data={
                        "cfg": reverse["cfg"],
                        "node_count": len(reverse["cfg"]),
                        "derived_from_unpack": reverse["derived_from_unpack"],
                        "target_executed": False,
                    },
                    reliability=0.8,
                    created_by="binary_analysis",
                )
            )

        raw_locations = logic.get("locations")
        locations = cls._enrich_logic_locations(
            raw_locations if isinstance(raw_locations, list) else [],
            reverse,
        )
        deobfuscation = logic.get("deobfuscation", {})
        decoded_count = (
            deobfuscation.get("decoded_count", 0)
            if isinstance(deobfuscation, Mapping)
            else 0
        )
        if locations or (isinstance(decoded_count, int) and decoded_count > 0):
            evidence.append(
                Evidence(
                    evidence_id=new_evidence_id(),
                    task_id=task_id,
                    evidence_type=EvidenceType.TOOL_RESULT,
                    source="binary_logic",
                    description=(
                        "Authentication, cryptography, registration and other high-value "
                        "logic clues localized from extracted facts and pseudocode."
                    ),
                    data={
                        "summary": logic.get("summary", {}),
                        "locations": locations,
                        "deobfuscation": (
                            dict(deobfuscation)
                            if isinstance(deobfuscation, Mapping)
                            else {}
                        ),
                    },
                    reliability=0.72,
                    created_by="binary_analysis",
                )
            )
            call_locations = [item for item in locations if item.get("call_chain")]
            if call_locations:
                evidence.append(
                    Evidence(
                        evidence_id=new_evidence_id(),
                        task_id=task_id,
                        evidence_type=EvidenceType.CALL_PATH,
                        source="binary_logic",
                        description=(
                            "Function-address and immediate CFG successor chains for "
                            "human validation of automatically tagged key logic."
                        ),
                        data={
                            "locations": call_locations,
                            "target_executed": False,
                        },
                        reliability=0.7,
                        created_by="binary_analysis",
                    )
                )

        signals = obfuscation.get("signals")
        score = obfuscation.get("score", 0)
        if (isinstance(signals, list) and signals) or (
            isinstance(score, (int, float)) and score > 0
        ) or bool(declared_protection):
            evidence.append(
                Evidence(
                    evidence_id=new_evidence_id(),
                    task_id=task_id,
                    evidence_type=EvidenceType.TOOL_RESULT,
                    source="binary_obfuscation",
                    description=(
                        "Packing or obfuscation heuristics were scored from static "
                        "facts; the score is an analysis hint, not a final verdict."
                    ),
                    data={
                        "score": score,
                        "base_score": obfuscation.get("base_score", 0),
                        "protection_category": protection_category,
                        "declared_protection": declared_protection,
                        "observed_methods": observed_methods,
                        "signals": signals if isinstance(signals, list) else [],
                        "limitations": obfuscation.get("limitations", []),
                    },
                    reliability=0.7,
                    created_by="binary_analysis",
                )
            )
        return evidence

    @staticmethod
    def _observed_protection_methods(
        packing: Any,
        signals: Any,
        *,
        derived_from_unpack: bool,
    ) -> list[str]:
        """Normalize static observations into stable, presentation-safe codes."""

        methods: list[str] = []
        if isinstance(packing, Mapping):
            raw_base = packing.get("signals")
            if isinstance(raw_base, list):
                methods.extend(str(item) for item in raw_base if item)
        if isinstance(signals, list):
            for item in signals:
                if not isinstance(item, Mapping):
                    continue
                value = item.get("name") or item.get("kind") or item.get("type")
                if value:
                    methods.append(str(value))
        if derived_from_unpack:
            methods.append("upx_unpack_copy")
        return list(dict.fromkeys(methods))

    @staticmethod
    def _tool_run_summaries(runs: Any) -> list[dict[str, Any]]:
        """Exclude commands and raw tool logs while preserving audit outcomes."""

        if not isinstance(runs, list):
            return []
        summaries: list[dict[str, Any]] = []
        for raw in runs:
            if not isinstance(raw, Mapping):
                continue
            facts = raw.get("facts")
            facts = facts if isinstance(facts, Mapping) else {}
            input_fact = facts.get("input")
            output_fact = facts.get("output")
            summaries.append(
                {
                    "tool": raw.get("tool", raw.get("stage", "unknown")),
                    "status": raw.get("status", "unknown"),
                    "executed": raw.get("executed", False),
                    "return_code": raw.get("return_code"),
                    "error": raw.get("error"),
                    "truncated": raw.get("truncated", False),
                    "input": dict(input_fact) if isinstance(input_fact, Mapping) else {},
                    "output": dict(output_fact) if isinstance(output_fact, Mapping) else {},
                    "function_count": len(facts.get("functions", []))
                    if isinstance(facts.get("functions"), list)
                    else 0,
                    "pseudocode_count": len(facts.get("pseudocode", {}))
                    if isinstance(facts.get("pseudocode"), Mapping)
                    else 0,
                    "cfg_node_count": len(facts.get("cfg", {}))
                    if isinstance(facts.get("cfg"), Mapping)
                    else 0,
                }
            )
        return summaries

    @classmethod
    def _enrich_logic_locations(
        cls,
        locations: list[Any],
        reverse: dict[str, Any],
    ) -> list[dict[str, Any]]:
        functions = reverse["functions"]
        cfg = reverse["cfg"]
        pseudocode = reverse["pseudocode"]
        names: dict[str, str] = {}
        for item in functions:
            address = item.get("address")
            if isinstance(address, int) and not isinstance(address, bool):
                names[f"0x{address:x}"] = str(item.get("name") or f"func@0x{address:x}")

        enriched: list[dict[str, Any]] = []
        for raw in locations:
            if not isinstance(raw, Mapping):
                continue
            item = dict(raw)
            address = item.get("address")
            address = str(address) if address else None
            code = pseudocode.get(address, "") if address else ""
            if not code:
                matched = str(item.get("matched", "")).casefold()
                located = next(
                    (
                        (candidate_address, candidate_code)
                        for candidate_address, candidate_code in pseudocode.items()
                        if matched and matched in candidate_code.casefold()
                    ),
                    None,
                )
                if located:
                    address, code = located
            if address:
                item["address"] = address
                item["function"] = item.get("function") or names.get(address) or f"func@{address}"
                item["call_chain"] = [address, *cfg.get(address, [])][:8]
            item["code_snippet"] = code[:12_000] if code else None
            item["rationale"] = cls._logic_rationale(item)
            item["review_status"] = "pending_human_review"
            enriched.append(item)
        return enriched

    @staticmethod
    def _logic_rationale(item: Mapping[str, Any]) -> str:
        source = str(item.get("source", "extracted fact"))
        category = str(item.get("category", "key logic"))
        matched = str(item.get("matched", ""))
        return (
            f"{source} fact matched the {category} semantic dictionary"
            + (f": {matched[:96]}" if matched else "")
            + "; this is a review clue, not a vulnerability verdict."
        )

    @staticmethod
    def _first_pseudocode_match(
        pseudocode: Mapping[str, str],
        matched_symbols: list[str],
        functions: list[dict[str, Any]],
    ) -> dict[str, Any]:
        names: dict[str, str] = {}
        for item in functions:
            address = item.get("address")
            if isinstance(address, int) and not isinstance(address, bool):
                names[f"0x{address:x}"] = str(item.get("name") or f"func@0x{address:x}")
        wanted = {value.casefold() for value in matched_symbols}
        for address, code in pseudocode.items():
            tokens = set(_SYMBOL_TOKEN.findall(code.casefold()))
            if wanted.intersection(tokens):
                return {
                    "address": address,
                    "function": names.get(address, f"func@{address}"),
                    "code_snippet": code[:12_000],
                }
        return {}

    @staticmethod
    def _risky_symbols(
        imports: list[str],
        strings: list[str],
        *,
        allow_embedded_text: bool = False,
    ) -> list[str]:
        """Return explicit risky symbols without substring-only false matches.

        Some C runtimes route both bounded ``snprintf`` and unbounded
        ``sprintf`` through an internal ``__stdio_common_vsprintf`` helper.
        That helper is therefore deliberately not treated as a vulnerability
        signal.  Exact or recognizably decorated public symbol names are
        retained; ambiguous runtime implementation details remain available to
        the logic analyzer as auxiliary evidence.
        """
        matches: set[str] = set()
        for value in imports:
            for token in _SYMBOL_TOKEN.findall(str(value).casefold()):
                variants = {token, token.lstrip("_").split("@", 1)[0]}
                pending = list(variants)
                for variant in pending:
                    for prefix in _KNOWN_SYMBOL_PREFIXES:
                        if variant.startswith(prefix):
                            variants.add(variant.removeprefix(prefix))
                matches.update(RISKY_SYMBOLS.intersection(variants))
        for value in strings:
            text = str(value).casefold()
            for token in _SYMBOL_TOKEN.findall(text):
                variants = {token, token.lstrip("_").split("@", 1)[0]}
                pending = list(variants)
                for variant in pending:
                    for prefix in _KNOWN_SYMBOL_PREFIXES:
                        if variant.startswith(prefix):
                            variants.add(variant.removeprefix(prefix))
                risky = RISKY_SYMBOLS.intersection(variants)
                # ``system`` is also a common English noun in compiler/runtime
                # messages (for example "read only file system").  Treat it as
                # a symbol only when the string itself looks like a symbol or
                # when the caller explicitly supplies decompiled code text.
                if "system" in risky:
                    literal = text.strip()
                    explicit_literal = re.fullmatch(
                        r"(?:(?:[a-z0-9_.-]+)!)?(?:(?:__imp_|_imp__|ucrt_)?_?system)(?:@\d+)?",
                        literal,
                    )
                    decompiled_call = allow_embedded_text and re.search(
                        r"(?<![a-z0-9_])system\s*\(",
                        text,
                    )
                    if not explicit_literal and not decompiled_call:
                        risky = set(risky) - {"system"}
                matches.update(risky)
        return sorted(matches)

    @classmethod
    def _binary_locator(
        cls,
        analysis: BinaryAnalysisResult,
        pseudocode_location: Mapping[str, Any],
        semantic_callsites: list[dict[str, Any]],
        matched_symbols: list[str],
        functions: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Return the most precise honest locator available for a binary signal.

        A PE/ELF without debug information cannot be mapped back to an original
        source file and line.  This helper therefore reports, in descending
        precision, a decompiled function address, a decoded instruction
        call-site, an import-table slot, an extracted-string file offset, or the
        binary image itself.  The precision label is carried in metadata so the
        frontend does not present an IAT/string location as source code.
        """

        address = cls._format_binary_address(pseudocode_location.get("address"))
        if address:
            return {
                "binary_address": address,
                "function_name": pseudocode_location.get("function"),
                "located_symbol": matched_symbols[0] if matched_symbols else None,
                "locator_kind": "decompiled_function",
                "locator_precision": "function_address",
            }

        for callsite in semantic_callsites:
            raw_address = callsite.get("address")
            address = cls._format_binary_address(raw_address)
            if not address:
                continue
            numeric_address = raw_address if isinstance(raw_address, int) else None
            return {
                "binary_address": address,
                "function_name": cls._function_containing(functions, numeric_address),
                "located_symbol": callsite.get("inferred_api"),
                "locator_kind": "decoded_callsite",
                "locator_precision": "instruction_address",
            }

        wanted = {value.casefold() for value in matched_symbols}
        format_details = analysis.metadata.get("format_details")
        if isinstance(format_details, Mapping):
            import_entries = format_details.get("import_entries")
            if isinstance(import_entries, list):
                for raw in import_entries:
                    if not isinstance(raw, Mapping):
                        continue
                    symbol = str(raw.get("symbol") or "")
                    matched = cls._risky_symbols([symbol], [])
                    if not wanted.intersection(value.casefold() for value in matched):
                        continue
                    address = cls._format_binary_address(raw.get("iat_address"))
                    if address:
                        return {
                            "binary_address": address,
                            "function_name": None,
                            "located_symbol": symbol,
                            "locator_kind": "import_table",
                            "locator_precision": "iat_address",
                        }

        string_locations = analysis.metadata.get("string_locations")
        if isinstance(string_locations, list):
            for raw in string_locations:
                if not isinstance(raw, Mapping):
                    continue
                value = str(raw.get("value") or "")
                located = cls._risky_symbols([], [value])
                if not wanted.intersection(item.casefold() for item in located):
                    continue
                offset = raw.get("offset")
                if isinstance(offset, int) and not isinstance(offset, bool):
                    return {
                        "binary_address": None,
                        "function_name": None,
                        "located_symbol": located[0],
                        "binary_file_offset": f"0x{offset:x}",
                        "locator_kind": "string_offset",
                        "locator_precision": "file_offset",
                    }

        return {
            "binary_address": None,
            "function_name": None,
            "located_symbol": matched_symbols[0] if matched_symbols else None,
            "locator_kind": "binary_image",
            "locator_precision": "image_only",
        }

    @staticmethod
    def _format_binary_address(value: Any) -> str | None:
        if isinstance(value, int) and not isinstance(value, bool):
            return f"0x{value:x}"
        if isinstance(value, str) and value.strip():
            return value.strip()
        return None

    @staticmethod
    def _function_containing(
        functions: list[dict[str, Any]],
        address: int | None,
    ) -> str | None:
        if address is None:
            return None
        for item in functions:
            start = item.get("address")
            if not isinstance(start, int) or isinstance(start, bool):
                continue
            size = item.get("size")
            bounded_size = size if isinstance(size, int) and size > 0 else 1
            if start <= address < start + bounded_size:
                return str(item.get("name") or f"func@0x{start:x}")
        return None

    @staticmethod
    def _risky_callsites(metadata: dict[str, Any]) -> list[dict[str, Any]]:
        """Select high-confidence, non-executing call-site risk facts.

        The structural analyzer owns decoding and provenance.  This Agent only
        accepts the narrow, versioned classification for an unbounded UCRT
        format-write shape; bounded or unknown helper calls remain auxiliary
        facts and cannot become findings here.
        """
        semantics = metadata.get("callsite_semantics")
        if not isinstance(semantics, dict):
            return []
        if (
            semantics.get("schema_version") != 1
            or semantics.get("analyzer") != "pe-x64-callsite-semantics"
            or semantics.get("available") is not True
            or semantics.get("target_executed") is not False
        ):
            return []
        callsites = semantics.get("callsites")
        if not isinstance(callsites, list):
            return []
        return [
            dict(item)
            for item in callsites
            if isinstance(item, dict)
            and item.get("classification") == "unbounded_format_write"
            and item.get("inferred_api") == "sprintf"
            and isinstance(item.get("confidence"), (int, float))
            and not isinstance(item.get("confidence"), bool)
            and float(item["confidence"]) >= 0.85
        ]
