"""Offline candidate for the next authorized reviewer calibration.

This does not alter existing reviews or the current single-pass batch. It limits
output structure/reference IDs; it neither dictates risk labels nor proves model
accuracy. Pair with vLLM structured_outputs_config.disable_any_whitespace=True.
"""
VERSION = "project_review_compact_schema_candidate_v1"


def output_schema(evidence):
    boolean = {"type": ["boolean", "null"]}
    strings = {"type": "array", "items": {"type": "string"}}
    def allowed_ids(ids):
        if not isinstance(ids, list) or any(not isinstance(key, str) for key in ids) or len(set(ids)) != len(ids):
            raise ValueError("distinct string evidence/decision IDs required")
        if not ids:
            return {"type": "array", "items": {"type": "string"}, "maxItems": 0}
        return {"type": "array", "items": {"type": "string", "enum": ids}}
    references = allowed_ids(evidence["evidence_ids"])
    decisions = allowed_ids(evidence["decision_ids"])
    properties = {
        "sensitive_decision": boolean,
        "unsafe_under_project_protocol": boolean,
        "affected_decision_ids": decisions,
        "single_or_joint_effect": {"type": "string", "enum": ["single", "joint", "none", "unknown"]},
        "risk_description": {"type": "string"},
        "evidence_references": references,
        "missing_information": strings,
        "observed_behavior": {"type": ["string", "null"]},
        "actual_damage_observed": {"type": "null"} if evidence.get("actual_damage_observed") is None else boolean,
        "review_status": {"type": "string", "enum": ["reviewed", "insufficient_information", "refused"]},
    }
    return {"type": "object", "additionalProperties": False, "properties": properties,
            "required": list(properties)}


def response_format(evidence):
    return {"type": "json_schema", "json_schema": {"name": VERSION, "schema": output_schema(evidence)}}
