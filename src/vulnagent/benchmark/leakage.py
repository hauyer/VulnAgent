"""WP5: label-leakage guard for blind evaluation.

Distinguishes *hard leaks* (case-specific answers: fixed commit, trigger
input, patch, exact location, unique description phrases) from *knowledge
overlap* (generic CWE taxonomy terms the agent may legitimately know).
The guard is run before a case is allowed into the blind set.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from vulnagent.benchmark.schema import (
    BlindCaseManifest,
    GroundTruth,
    LabelLeakReport,
)

# Generic CWE taxonomy terms are legitimate security knowledge, not leaks.
_KNOWLEDGE_TERMS = (
    "CWE-",
    "buffer overflow",
    "use-after-free",
    "command injection",
    "sql injection",
    "path traversal",
    "stack-buffer-overflow",
    "heap-buffer-overflow",
    "integer overflow",
)


@dataclass(slots=True)
class LabelLeakageGuard:
    """Checks that no answer artifact reaches the agent-visible text."""

    def _is_generic(self, phrase: str) -> bool:
        """Generic phrases are shared across samples; not a hard leak."""
        lowered = phrase.lower()
        return (
            lowered in ("the vulnerability", "an attacker", "the program")
            or re.fullmatch(r"[a-z\s'\"-]{0,20}", lowered) is not None
        )

    def _tokens(self, gt: GroundTruth) -> dict[str, str]:
        return {
            "fixed_commit": gt.fixed_commit,
            "trigger_input": gt.trigger_input,
            "patch_hint": gt.patch_hint,
            "location": gt.location,
            "title": gt.title,
            "description": gt.description,
        }

    def check(
        self,
        manifest: BlindCaseManifest,
        gt: GroundTruth,
        prompt_text: str,
        metadata_text: str,
    ) -> LabelLeakReport:
        """Scan agent-visible text for hard leaks and knowledge overlaps."""
        hard_leaks: list[str] = []
        overlap: list[str] = []
        visible = f"{prompt_text}\n{metadata_text}"
        visible_lower = visible.lower()

        for name, value in self._tokens(gt).items():
            token = value.strip()
            if not token:
                continue
            token_lower = token.lower()
            if name in ("title", "description"):
                # Only distinctive phrases count; strip generic shell words.
                if len(token) < 8:
                    continue
                phrases = [p.strip() for p in re.split(r"[,.;:()]", token) if p.strip()]
                distinctive = [p for p in phrases if len(p) >= 8 and not self._is_generic(p)]
                if distinctive and any(p.lower() in visible_lower for p in distinctive):
                    hard_leaks.append(name)
            elif token_lower in visible_lower or token_lower.splitlines()[0] in visible_lower:
                hard_leaks.append(name)
            elif name == "fixed_commit" and len(token) >= 7 and token[:7].lower() in visible_lower:
                hard_leaks.append(name)

        # Knowledge overlap: generic CWE terms that appear in the visible text.
        for term in _KNOWLEDGE_TERMS:
            if term.lower() in visible_lower:
                overlap.append(term)

        # The manifest must never reference the GT path or label fields.
        if manifest.ground_truth_ref and manifest.ground_truth_ref in visible:
            hard_leaks.append("ground_truth_ref")

        return LabelLeakReport(
            clean=not hard_leaks,
            hard_leaks=hard_leaks,
            knowledge_overlap=overlap,
        )
