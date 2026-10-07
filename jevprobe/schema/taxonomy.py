"""Frozen taxonomy enums (S11 v1.4).

Internal names are UPPERCASE enums; JSON serialization is lowercase — this is
the single convention preventing Choice/choice/CHOICE statistics pollution.
"""
from enum import Enum


class _Taxonomy(Enum):
    @classmethod
    def values(cls) -> list[str]:
        return [e.value for e in cls]

    def to_json(self) -> str:
        return self.value


class SurfaceType(_Taxonomy):
    """How the Jev output is CONSUMED downstream (decision consumption pattern)."""
    CHOICE = "choice"
    SCORE = "score"
    UNCERTAINTY = "uncertainty"
    RANKING = "ranking"


class SinkType(_Taxonomy):
    """Frozen six classes — no further extension (S11 v1.4)."""
    TOOL_EXECUTION = "tool_execution"
    FILE_MODIFICATION = "file_modification"
    CODE_EXECUTION = "code_execution"
    PERMISSION_CHANGE = "permission_change"
    CREDENTIAL_OPERATION = "credential_operation"
    EXTERNAL_SIDE_EFFECT = "external_side_effect"


class SourceType(_Taxonomy):
    """Where the attacker-controlled information comes from (trust domain)."""
    USER = "user"
    WEB = "web"
    FILE = "file"
    TOOL = "tool"
    MCP = "mcp"
    MEMORY = "memory"
    DATABASE = "database"
    AGENT_STATE = "agent_state"


class InjectionLocation(_Taxonomy):
    """Where the payload lands inside the Jev input structure."""
    INSTRUCTION = "instruction"
    QUESTION = "question"
    EVIDENCE = "evidence"
    RETRIEVED_CONTEXT = "retrieved_context"
    TOOL_RESULT = "tool_result"
    OPTION_DESCRIPTION = "option_description"
    METADATA = "metadata"
    CONVERSATION_HISTORY = "conversation_history"
    MEMORY_FIELD = "memory_field"


class TransformationDimension(_Taxonomy):
    INSTRUCTIONAL_INFLUENCE = "instructional_influence"
    SEMANTIC_FRAMING = "semantic_framing"
    CONTEXT_AUGMENTATION = "context_augmentation"
    INFORMATION_ORDERING = "information_ordering"
    METADATA_MANIPULATION = "metadata_manipulation"


class VisibilityLevel(_Taxonomy):
    """Categories, NOT an ordering of attack strength (S11 v1.2/v1.4)."""
    S1_EXPLICIT = "s1_explicit"
    S2_ARTIFACT_BASED = "s2_artifact_based"
    S3_CONTEXTUAL = "s3_contextual"
    S4_SEMANTIC_ONLY = "s4_semantic_only"


class SemanticPreservation(_Taxonomy):
    PRESERVED = "preserved"
    PARTIALLY_PRESERVED = "partially_preserved"
    NOT_PRESERVED = "not_preserved"


class AttackGoal(_Taxonomy):
    TARGET_CHOICE = "target_choice"
    THRESHOLD_CROSSING = "threshold_crossing"
    RANKING_CHANGE = "ranking_change"
    CONFIDENCE_DEGRADATION = "confidence_degradation"
    BEHAVIOR_CHANGE = "behavior_change"


# Surface type -> its divergence metric (v1.4 frozen formulas)
SURFACE_METRIC = {
    SurfaceType.CHOICE: "DFR",
    SurfaceType.SCORE: "TCR",
    SurfaceType.RANKING: "RDR",
    SurfaceType.UNCERTAINTY: "USS",
}
