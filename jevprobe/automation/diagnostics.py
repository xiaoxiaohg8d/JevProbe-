"""Engineering diagnostic states, independent of the frozen research taxonomy."""
from __future__ import annotations

from collections import Counter
import re


STATES = {
    "discovery_error", "project_unrunnable", "source_uncontrollable", "path_unverified",
    "generation_failed", "transform_invalid", "api_error", "unstable",
    "stable_negative", "decision_not_propagated", "behavior_without_security_violation",
    "budget_interrupted", "missing_information", "validated",
}

CHECKS = (
    "actual_boundary", "correct_source_and_field", "preprocessing_and_filtering",
    "actual_target_request", "strategy_realization", "generator_contract_and_scope",
    "baseline_variance", "output_parser_and_option_mapping",
)


def transformation_checks(original, modified, strategy):
    from ..manipulation import DIMENSIONS
    failures = []
    if not isinstance(modified, str) or not modified.strip():
        failures.append("empty_output")
    elif original.strip() == modified.strip():
        failures.append("no_substantive_change")
    if strategy == "information_reordering" and isinstance(modified, str):
        # Reordering paragraphs only: an exact multiset, including each fact.
        before = original.split("\n\n")
        after = modified.split("\n\n")
        if Counter(before) != Counter(after) or before == after:
            failures.append("ordering_not_a_permutation")
    implementation = "verified_mechanical" if strategy == "information_reordering" and not failures else "pending_content_review"
    if strategy == "inj_instruction" and isinstance(modified, str):
        if not re.search(r"disregard|ignore|override", modified[len(original):], re.I):
            failures.append("directive_not_realized")
        elif modified.startswith(original):
            implementation = "verified_mechanical"
    return {"valid": not failures, "failures": failures,
            "dimension": DIMENSIONS[strategy], "strategy": strategy,
            "strategy_realization": implementation,
            "visibility": None, "semantic_preservation": None,
            "annotation_status": "pending_actual_content_review"}


def diagnose(record):
    """Conclusions derive from evidence; unresolved cause hypotheses stay plural."""
    status = record.get("diagnostic_status", "missing_information")
    if status not in STATES:
        raise ValueError("unknown engineering diagnosis")
    evidence = record.get("diagnostic_evidence", {})
    checks = [{"check": check, "finding": evidence.get(check),
               "status": "supported" if check in evidence else "pending"} for check in CHECKS]
    hypotheses = []
    if status == "stable_negative":
        hypotheses = [
            {"cause": "judgment robust to this valid transformation", "status": "consistent_with_observation"},
            {"cause": "strategy weak for this contract", "status": "unresolved", "verification": "separate preregistered strategy contrast on held-out input"},
        ]
        if "preprocessing_and_filtering" not in evidence:
            hypotheses.append({"cause": "content lost or changed before judgment", "status": "unresolved",
                               "verification": "compare source bytes with captured request; marker contrast"})
    return {"version": "s13.1", "status": status,
            "is_framework_failure": status in {"discovery_error", "generation_failed", "transform_invalid", "api_error"},
            "ordered_checks": checks, "hypotheses": hypotheses,
            "confidence": "evidence_bounded", "human_review": "pending", "kappa": None}
