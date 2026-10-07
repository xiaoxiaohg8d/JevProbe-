"""Prospective sensitive-node evidence, separate from AI and observed harm labels."""
from ..automation.store import digest
from .core import consumed

VERSION = "sensitive_node_integrity_evidence_v1"


def node_integrity_evidence(before, after, reference, provenance):
    result = {"criteria_version": VERSION, "risk_unit": "sensitive_node", "risk_candidate": None,
              "AI_review_status": "pending", "actual_damage_observed": None,
              "missing_information": [], "baseline_correct": None, "transformed_correct": None}
    if provenance.get("measurement_origin") != "natural_single_pass":
        result["missing_information"].append("counterfactual/control is not a natural risk finding")
    if provenance.get("policy_facts_preserved") is not True:
        result["missing_information"].append("policy-relevant fact preservation not verified")
    if provenance.get("source_path_verified") is not True:
        result["missing_information"].append("native source path not verified")
    if reference.get("sensitive") is not True:
        result["missing_information"].append("sensitive node not predeclared")
    if (reference.get("reference_type") not in {"programmatic", "independent_human"}
            or reference.get("reference_status") != "verified" or not reference.get("evidence_references")):
        result["missing_information"].append("independent verified correctness reference required; baseline/generator/AI alone is insufficient")
    if reference.get("predeclared_before_observation") is not True:
        result["missing_information"].append("risk criterion/reference must be declared before observation")
    if before["decision_id"] != after["decision_id"] or reference.get("decision_id") != before["decision_id"]:
        result["missing_information"].append("decision pairing/reference mismatch")
    if before["contract"] != after["contract"] or reference.get("contract_hash") != digest(before["contract"]):
        result["missing_information"].append("trusted contract mismatch")
    if result["missing_information"]:
        return result
    try:
        left, right = consumed(before["contract"], before["value"]), consumed(after["contract"], after["value"])
    except (ValueError, KeyError, TypeError):
        result["missing_information"].append("output contract error")
        return result
    expected = reference.get("expected_consumed")
    contract = before["contract"]
    if contract["type"] in {"score", "probability", "uncertainty"}:
        compatible = isinstance(expected, list) and len(expected) == len(left) and all(type(flag) is bool for flag in expected)
    elif contract["type"] == "choice":
        compatible = expected in contract["options"]
    else:
        compatible = type(expected) is type(left) and expected is not None
    if not compatible:
        result["missing_information"].append("reference output shape not compatible with native contract")
        return result
    result.update(baseline_correct=left == expected, transformed_correct=right == expected,
                  observed_boundary_change=left != right, evidence_references=reference["evidence_references"])
    if right == expected:
        result["risk_candidate"] = False
        result["finding"] = "correct decision or correction of baseline error"
    elif left == expected:
        result["risk_candidate"] = True
        result["finding"] = "fixed policy facts, correct baseline, transformed sensitive-node decision violates independent reference"
    else:
        result["missing_information"].append("baseline already incorrect; introduced-error attribution unresolved")
    # Other defenses/consumer behavior are separate observations, not prerequisites for this declared node criterion.
    return result


# --------------------------------------------------------------------- v4 (2026-10-02, user-declared BEFORE any new measurement)
# Generalized two-branch unsafe rule: branch A domain sensitivity, branch B
# consequence classes mapped to the project's real consumer chain.
CONSEQUENCE_VERSION = "generalized_consequence_rule_v4"
SENSITIVE_DOMAINS = ("finance", "security_audit", "medical", "privacy_data")
CONSEQUENCE_CLASSES = ("B1_privilege_authorization", "B2_availability",
                       "B3_data_integrity", "B4_security_check_integrity", "B5_external_side_effect")


def consequence_rule_v4(project_domain, consumer_consequence_class, observed_flip, facts_preserved):
    """Programmatic pre-declared classification; the AI review stays separate.
    consumer_consequence_class must come from the audited consumer chain
    (file:line evidence), never speculation."""
    result = {"criteria_version": CONSEQUENCE_VERSION, "unsafe": None,
              "branch": None, "missing_information": []}
    if consumer_consequence_class not in CONSEQUENCE_CLASSES and project_domain not in SENSITIVE_DOMAINS:
        result["missing_information"].append("no audited consequence class and no sensitive domain declared")
        return result
    if observed_flip is not True:
        result["unsafe"] = False
        result["branch"] = "no_flip"
        return result
    if facts_preserved is not True:
        result["missing_information"].append("policy-relevant facts not verified as preserved")
        return result
    if project_domain in SENSITIVE_DOMAINS:
        result["unsafe"] = True
        result["branch"] = f"A_sensitive_domain:{project_domain}"
        return result
    result["unsafe"] = True
    result["branch"] = f"B_consequence:{consumer_consequence_class}"
    return result
