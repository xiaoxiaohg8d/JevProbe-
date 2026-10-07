"""Offline, evidence-linked diagnosis without changing experimental labels."""
from __future__ import annotations

from .core import CHECKS, compare, consumed, number, source_variant
from ..automation.store import digest
from .generation_quality import artifact_findings

VERSION = "single_pass_evidence_diagnostics_v1"


def boundary_distances(decision):
    contract = decision["contract"]
    value = consumed(contract, decision.get("value"))  # Validate before deriving distances.
    if contract["type"] not in {"score", "probability", "uncertainty"}:
        return []
    return [{"operator": boundary["operator"], "threshold": boundary["threshold"],
             "signed_distance": number(decision["value"]) - number(boundary["threshold"]),
             "condition": condition}
            for boundary, condition in zip(contract["boundaries"], value)]


def _field(value, dotted):
    for part in dotted.split("."):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


def any_consumer_analysis(record, contract):
    """Check a declared OR consumer, never infer a rule from outcome alone."""
    if contract["type"] != "any":
        raise ValueError("consumer analyzer supports declared any only")
    ids = contract["decision_ids"]
    if not ids or len(set(ids)) != len(ids):
        raise ValueError("consumer binding requires distinct nonempty decision IDs")
    sides = {}
    for name, execution in (("before", record["baseline"]), ("after", record["transformed"])):
        indexed = {d["decision_id"]: d for d in execution["decisions"]}
        if len(indexed) != len(execution["decisions"]) or not set(ids) <= indexed.keys():
            return {"status": "missing_or_duplicate_consumer_node", "behavior_change": None}
        flags = {}
        for key in ids:
            flags[key] = consumed(indexed[key]["contract"], indexed[key]["value"])
            if len(flags[key]) != 1 or type(flags[key][0]) is not bool:
                raise ValueError("declared OR requires one boolean boundary per node")
        flags = {key: flag[0] for key, flag in flags.items()}
        observed = _field(execution["behavior"], contract["behavior_field"])
        expected = any(flags.values())
        sides[name] = {"conditions": flags, "active_nodes": [key for key in ids if flags[key]],
                       "expected_behavior": expected, "observed_behavior": observed}
        if type(observed) is not bool or observed != expected:
            return {"status": "consumer_evidence_mismatch", "sides": sides, "behavior_change": None}
    changed = [key for key in ids if sides["before"]["conditions"][key] != sides["after"]["conditions"][key]]
    before, after = sides["before"]["expected_behavior"], sides["after"]["expected_behavior"]
    return {"status": "verified_against_recorded_native_behavior", "sides": sides,
            "changed_nodes": changed, "behavior_change": before != after,
            "changed_nodes_masked_by_OR": bool(changed) and before == after,
            "nodes_that_must_clear_for_suppression_at_baseline": sides["before"]["active_nodes"],
            "warning_suppressed": before and not after,
            "counterfactual_not_executed": True}


def diagnose_record(record, case, consumer_contract=None):
    checks = {name: {"status": "pending", "evidence": []} for name in CHECKS}
    output = {"version": VERSION, "case_id": record["case_id"], "slot": record["slot"],
              "record_status": record["status"], "checks": checks, "hypotheses": [],
              "review_status": record.get("risk", {}).get("review_status", "pending"),
              "baseline_variance": "unmeasured_single_pass", "changes_existing_labels": False}
    generation = record.get("generation", {})
    source = generation.get("source")
    output["generation_artifact_findings"] = artifact_findings(
        source[len(case["original_source"]):] if isinstance(source, str) and source.startswith(case["original_source"]) else None)
    checks["generator_contract_and_scope"] = {
        "status": "recorded", "evidence": ["case.source_scope", "record.generation.checks"],
        "findings": generation.get("checks")}
    checks["strategy_realization"] = {
        "status": "mechanical_only", "evidence": ["record.generation.source"],
        "findings": {"declared_strategy": generation.get("strategy"),
                     "mechanical": generation.get("checks", {}).get("strategy_realization"),
                     "semantic_review": "pending"}}
    if record["status"] != "measured":
        output["diagnostic_status"] = record["status"]
        return output
    comparison = compare(record["baseline"]["decisions"], record["transformed"]["decisions"])
    checks["actual_boundary"] = {"status": "verified" if comparison == record["comparison"] else "mismatch",
                                 "evidence": ["record.baseline.decisions", "record.transformed.decisions"],
                                 "findings": comparison}
    field = case["source_scope"]["request_field"]
    captures = []
    contracts_unchanged = True
    baseline_requests = {r["ordinal"]: r for r in record["baseline"]["requests"]}
    for request in record["transformed"]["requests"]:
        captured = _field(request["request"], field)
        captures.append({"ordinal": request["ordinal"], "request_hash": digest(request["request"]),
                         "saved_hash_matches": digest(request["request"]) == request["request_hash"],
                         "exact_source_match": captured == generation.get("source"),
                         "original_prefix_present": isinstance(captured, str) and captured.startswith(case["original_source"]),
                         "captured_chars": len(captured) if isinstance(captured, str) else None})
        baseline_request = baseline_requests.get(request["ordinal"])
        contracts_unchanged &= baseline_request is not None and baseline_request["request"]["questions"] == request["request"]["questions"]
    source_verified = bool(captures) and all(c["exact_source_match"] for c in captures)
    checks["correct_source_and_field"] = {"status": "verified" if source_verified else "requires_adapter_specific_analysis",
                                          "evidence": ["case.source_scope", "record.transformed.requests"], "findings": captures}
    checks["preprocessing_and_filtering"] = {"status": "exact_capture" if source_verified else "unresolved",
                                              "evidence": ["record.generation.source", "record.transformed.requests"],
                                              "finding": "No source bytes lost in recorded field" if source_verified else "Inspect native preprocessing; mismatch alone is not a source-control failure"}
    checks["actual_target_request"] = {"status": "recorded", "evidence": ["record.baseline.requests", "record.transformed.requests"],
                                        "trusted_questions_unchanged": contracts_unchanged}
    checks["output_parser_and_option_mapping"] = {
        "status": "verified" if comparison["unpaired_or_invalid"] == 0 else "incomplete",
        "evidence": ["record.comparison"], "paired_values": comparison["paired_values"]}
    checks["baseline_variance"] = {"status": "unmeasured", "evidence": [], "reason": "single-pass protocol, no repeat calls"}
    output["boundary_distances"] = {side: [{"decision_id": d["decision_id"], "distances": boundary_distances(d)}
                                             for d in record[key]["decisions"]]
                                    for side, key in (("before", "baseline"), ("after", "transformed"))}
    output["source_scope_recheck"] = source_variant(case, generation.get("source"), strategy=generation.get("strategy"))
    if consumer_contract:
        output["consumer_analysis"] = any_consumer_analysis(record, consumer_contract)
    output["diagnostic_status"] = ("comparison_incomplete" if comparison["unpaired_or_invalid"] else
                                   "observed_flip" if comparison["observed_flip"] else "observed_negative")
    if comparison["observed_flip"] is False:
        output["hypotheses"] = [
            {"cause": "judgment resists this particular transformation", "status": "consistent_with_observation"},
            {"cause": "strategy may be ineffective for this boundary", "status": "unresolved"},
            {"cause": "baseline stochastic variation", "status": "unmeasured"},
        ]
    if output.get("consumer_analysis", {}).get("changed_nodes_masked_by_OR"):
        output["hypotheses"].append({"cause": "other active nodes preserve the OR behavior",
                                      "status": "supported_by_native_values_and_behavior"})
    return output
