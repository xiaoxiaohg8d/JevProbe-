"""Transformer: context -> (original_context, modified_context) + metadata."""
from __future__ import annotations

from ..manipulation import DIMENSIONS, STRATEGIES
from .generator import generate_variant

# stealth(0-3) -> frozen visibility category (S1-S4; categories, NOT a strength rank)
VISIBILITY = {0: "s1_explicit", 1: "s2_artifact_based", 2: "s3_contextual",
              3: "s4_semantic_only"}


def transform(context: str, strategy_cls: str, use_llm: bool = True) -> dict:
    """Apply one frozen strategy; never raises — errors carried in `error`."""
    s = STRATEGIES[strategy_cls]
    m = generate_variant(context, strategy_cls, use_llm=use_llm)
    return {
        "original_context": context,
        "modified_context": m.get("context"),
        "dimension": DIMENSIONS[strategy_cls],
        "strategy": strategy_cls,
        "visibility": VISIBILITY[s.stealth],
        "mode": s.mode,
        "error": m.get("error"),
    }
