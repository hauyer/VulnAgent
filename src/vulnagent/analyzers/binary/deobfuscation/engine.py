"""Deterministic, evidence-preserving recovery of common OLLVM patterns."""

from __future__ import annotations

import base64
import binascii
import re
from collections import deque
from collections.abc import Mapping
from typing import Any

from vulnagent.contracts import BinaryAnalysisResult


_SUBSTITUTIONS: tuple[tuple[re.Pattern[str], str, str], ...] = (
    (re.compile(r"\(([_A-Za-z]\w*)\s*\+\s*\(~([_A-Za-z]\w*)\s*\+\s*1\)\)"), r"(\1 - \2)", "add_not_inc_to_sub"),
    (re.compile(r"~\s*\(\s*~\s*([_A-Za-z]\w*)\s*\)"), r"\1", "double_not_elimination"),
    (re.compile(r"\b([_A-Za-z]\w*)\s*\^\s*0\b"), r"\1", "xor_zero_elimination"),
    (re.compile(r"\b([_A-Za-z]\w*)\s*\+\s*0\b"), r"\1", "add_zero_elimination"),
)
_OPAQUE_TRUE = re.compile(
    r"if\s*\(\s*\(\s*([_A-Za-z]\w*)\s*\*\s*\(\s*\1\s*-\s*1\s*\)\s*\)\s*&\s*1\s*\)\s*==\s*0\s*\)",
    re.IGNORECASE,
)
_BASE64 = re.compile(r"^[A-Za-z0-9+/]{8,}={0,2}$")
_HEX = re.compile(r"^(?:[0-9a-fA-F]{2}){4,}$")


class StaticDeobfuscationEngine:
    """Restore readability while retaining before/after evidence and limits."""

    async def restore(self, result: BinaryAnalysisResult) -> dict[str, Any]:
        metadata = result.metadata if isinstance(result.metadata, Mapping) else {}
        reverse = metadata.get("reverse_tool")
        pseudocode = reverse.get("pseudocode", {}) if isinstance(reverse, Mapping) else {}
        pseudocode = pseudocode if isinstance(pseudocode, Mapping) else {}
        cfg = self._cfg(result.cfg)
        entry = self._entry_node(metadata, cfg)
        reachable = self._reachable(cfg, entry)
        bogus_nodes = sorted(set(cfg).difference(reachable)) if entry else []
        dispatchers = self._dispatchers(cfg)
        runtime_edges = self._runtime_edges(metadata)
        restored_cfg = self._validated_cfg(cfg, runtime_edges, bogus_nodes)

        functions: list[dict[str, Any]] = []
        substitution_counts: dict[str, int] = {}
        opaque_predicates = 0
        for address, raw_code in list(pseudocode.items())[:256]:
            before = str(raw_code)[:24_000]
            after = before
            applied: list[str] = []
            for pattern, replacement, label in _SUBSTITUTIONS:
                after, count = pattern.subn(replacement, after)
                if count:
                    substitution_counts[label] = substitution_counts.get(label, 0) + count
                    applied.append(label)
            after, opaque_count = _OPAQUE_TRUE.subn("if (true /* proven parity identity */)", after)
            if opaque_count:
                opaque_predicates += opaque_count
                applied.append("opaque_predicate_annotation")
            if applied or address in dispatchers:
                functions.append({
                    "address": str(address),
                    "before": before,
                    "after": after,
                    "transformations": list(dict.fromkeys(applied)),
                    "dispatcher_candidate": str(address) in dispatchers,
                })

        decoded_strings = self._decode_strings(result.strings, metadata)
        detected = []
        if dispatchers:
            detected.append("control_flow_flattening")
        if bogus_nodes or opaque_predicates:
            detected.append("bogus_control_flow")
        if substitution_counts:
            detected.append("instruction_substitution")
        if decoded_strings:
            detected.append("string_encryption")
        before_score = self._readability_score(pseudocode, cfg, 0)
        after_map = {
            **{str(key): str(value) for key, value in pseudocode.items()},
            **{item["address"]: item["after"] for item in functions},
        }
        after_score = self._readability_score(after_map, restored_cfg, len(bogus_nodes))
        return {
            "schema_version": 1,
            "engine": "static-ollvm-deobfuscation",
            "supported_types": [
                "control_flow_flattening",
                "bogus_control_flow",
                "instruction_substitution",
                "string_encryption",
            ],
            "detected_types": detected,
            "control_flow": {
                "entry": entry,
                "dispatcher_candidates": dispatchers,
                "bogus_nodes_removed": bogus_nodes,
                "runtime_edge_validation_used": bool(runtime_edges),
                "original_node_count": len(cfg),
                "restored_node_count": len(restored_cfg),
                "restored_cfg": restored_cfg,
            },
            "instruction_recovery": {
                "substitution_counts": substitution_counts,
                "opaque_predicates_annotated": opaque_predicates,
                "functions": functions,
            },
            "string_recovery": {
                "decoded_count": len(decoded_strings),
                "items": decoded_strings,
            },
            "readability": {
                "before": before_score,
                "after": max(before_score, after_score),
                "improvement": max(0, after_score - before_score),
            },
            "limitations": [
                "dispatcher candidates are structural evidence, not proof of original source order",
                "only algebraically equivalent instruction substitutions are rewritten",
                "XOR strings require an extracted key in analyzer metadata",
                "LLM annotations never modify executable bytes",
            ],
        }

    @staticmethod
    def _cfg(raw: Any) -> dict[str, list[str]]:
        if not isinstance(raw, Mapping):
            return {}
        return {
            str(node): [str(target) for target in targets[:512]]
            for node, targets in list(raw.items())[:4096]
            if isinstance(targets, list)
        }

    @staticmethod
    def _entry_node(metadata: Mapping[str, Any], cfg: Mapping[str, list[str]]) -> str | None:
        entry = metadata.get("entry_point")
        candidates = [str(entry), hex(entry) if isinstance(entry, int) else ""]
        return next((item for item in candidates if item in cfg), next(iter(cfg), None))

    @staticmethod
    def _reachable(cfg: Mapping[str, list[str]], entry: str | None) -> set[str]:
        if entry is None:
            return set()
        seen: set[str] = set()
        queue = deque([entry])
        while queue and len(seen) <= 4096:
            node = queue.popleft()
            if node in seen:
                continue
            seen.add(node)
            queue.extend(target for target in cfg.get(node, []) if target in cfg and target not in seen)
        return seen

    @staticmethod
    def _dispatchers(cfg: Mapping[str, list[str]]) -> list[str]:
        incoming: dict[str, int] = {node: 0 for node in cfg}
        for targets in cfg.values():
            for target in targets:
                if target in incoming:
                    incoming[target] += 1
        return sorted(
            node for node, targets in cfg.items()
            if len(set(targets)) >= 3 and incoming.get(node, 0) >= 2
        )

    @staticmethod
    def _runtime_edges(metadata: Mapping[str, Any]) -> set[tuple[str, str]]:
        trace = metadata.get("runtime_trace")
        raw = trace.get("executed_edges", []) if isinstance(trace, Mapping) else []
        edges: set[tuple[str, str]] = set()
        if isinstance(raw, list):
            for item in raw[:20_000]:
                if isinstance(item, (list, tuple)) and len(item) == 2:
                    edges.add((str(item[0]), str(item[1])))
        return edges

    @staticmethod
    def _validated_cfg(
        cfg: Mapping[str, list[str]],
        runtime_edges: set[tuple[str, str]],
        bogus_nodes: list[str],
    ) -> dict[str, list[str]]:
        bogus = set(bogus_nodes)
        restored: dict[str, list[str]] = {}
        for node, targets in cfg.items():
            if node in bogus:
                continue
            kept = [target for target in targets if target not in bogus]
            if runtime_edges:
                observed = [target for target in kept if (node, target) in runtime_edges]
                kept = observed or kept
            restored[node] = list(dict.fromkeys(kept))
        return restored

    @staticmethod
    def _decode_strings(values: list[str], metadata: Mapping[str, Any]) -> list[dict[str, Any]]:
        decoded: list[dict[str, Any]] = []
        seen: set[str] = set()
        for value in values[:10_000]:
            text = str(value).strip()
            payload: bytes | None = None
            algorithm = ""
            try:
                if _HEX.fullmatch(text):
                    payload, algorithm = bytes.fromhex(text), "hex"
                elif _BASE64.fullmatch(text) and len(text) % 4 == 0:
                    payload, algorithm = base64.b64decode(text, validate=True), "base64"
            except (ValueError, binascii.Error):
                continue
            if payload is None:
                continue
            try:
                clear = payload.decode("utf-8").strip("\0")
            except UnicodeDecodeError:
                continue
            if len(clear) >= 4 and clear.isprintable() and clear not in seen:
                seen.add(clear)
                decoded.append({"algorithm": algorithm, "ciphertext": text[:256], "plaintext": clear[:1024], "key_source": "not_required"})

        specs = metadata.get("string_decoders", [])
        if isinstance(specs, list):
            for item in specs[:256]:
                if not isinstance(item, Mapping) or str(item.get("algorithm", "")).casefold() != "xor":
                    continue
                key = item.get("key")
                cipher_hex = item.get("cipher_hex")
                if not isinstance(key, int) or not 0 <= key <= 255 or not isinstance(cipher_hex, str):
                    continue
                try:
                    clear = bytes(byte ^ key for byte in bytes.fromhex(cipher_hex)).decode("utf-8").strip("\0")
                except (ValueError, UnicodeDecodeError):
                    continue
                if clear and clear.isprintable() and clear not in seen:
                    seen.add(clear)
                    decoded.append({"algorithm": "xor", "ciphertext": cipher_hex[:256], "plaintext": clear[:1024], "key": key, "key_source": "static_decoder_metadata"})
        return decoded[:256]

    @staticmethod
    def _readability_score(pseudocode: Mapping[Any, Any], cfg: Mapping[str, list[str]], removed: int) -> int:
        code = "\n".join(str(value) for value in pseudocode.values())
        penalty = min(55, code.count("goto") * 2 + code.count("case ") + max(0, len(cfg) - 20) // 4)
        bonus = min(20, removed * 2)
        return max(0, min(100, 70 - penalty + bonus))
