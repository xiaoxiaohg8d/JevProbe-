"""ContextTransformationRecord v2.4 (S11 frozen schema)."""
from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field


@dataclass
class ContextTransformationRecord:
    transformation_id: str
    surface_id: str
    surface_type: str            # choice|score|uncertainty|ranking
    source_type: str             # 8-class Source taxonomy (json name)
    injection_location: str      # 9-class Location taxonomy (json name)
    dimension: str               # 5 frozen transformation dimensions
    strategy: str                # realization strategy (frozen registry)
    visibility: str              # s1_explicit..s4_semantic_only (category, not rank)
    semantic_preservation: str   # preserved|partially_preserved|not_preserved
    attack_goal: str             # incl. behavior_change
    original_context: str
    modified_context: str
    decision_before: object = None
    decision_after: object = None
    decision_signal: dict = field(default_factory=dict)   # {type, before, after} or {type:"none"}
    repeatability: dict = field(default_factory=dict)     # {original_trials, modified_trials, aggregation, distributions}
    judge_config: str = ""
    impact: dict = field(default_factory=lambda: {"evidence_levels": [], "evidence_items": []})

    def to_dict(self) -> dict:
        return asdict(self)


def make_transformation_id(repo: str, surface_id: str, strategy: str, context: str) -> str:
    h = hashlib.sha256(f"{repo}|{surface_id}|{strategy}|{context}".encode()).hexdigest()[:12]
    return f"T-{h}"
