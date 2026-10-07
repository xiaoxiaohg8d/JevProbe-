"""Compile predeclared consumer conditions, never optimize against model answers."""
from copy import deepcopy

from ..automation.store import digest
from .core import OPS, number

VERSION = "consumer_condition_plan_v1"
NEGATE = {">": "<=", ">=": "<", "<": ">=", "<=": ">", "==": "!=", "!=": "=="}


def validate(expression, node_ids):
    kind = expression.get("kind")
    if kind in {"any", "all"}:
        children = expression.get("children")
        if not isinstance(children, list) or not children:
            raise ValueError("nonempty consumer conditions required")
        for child in children:
            validate(child, node_ids)
    elif kind == "not":
        validate(expression["child"], node_ids)
    elif kind in {"numeric", "choice"}:
        if expression["decision_id"] not in node_ids:
            raise ValueError("consumer references an unverified decision")
        if kind == "numeric":
            if expression["operator"] not in OPS:
                raise ValueError("unsupported native comparison")
            number(expression["threshold"])
        elif not isinstance(expression.get("accepted"), list) or not expression["accepted"]:
            raise ValueError("nonempty native choice set required")
    else:
        raise ValueError("unknown consumer condition")
    return expression


def evaluate(expression, values):
    kind = expression["kind"]
    if kind == "any":
        return any([evaluate(child, values) for child in expression["children"]])
    if kind == "all":
        return all([evaluate(child, values) for child in expression["children"]])
    if kind == "not":
        return not evaluate(expression["child"], values)
    if kind == "numeric":
        return OPS[expression["operator"]](number(values[expression["decision_id"]]), number(expression["threshold"]))
    if kind == "choice":
        return values[expression["decision_id"]] in expression["accepted"]
    raise ValueError("unknown consumer condition")


def requirements(expression, desired):
    """Symbolic constraints retain OR alternatives; no Cartesian search or forced output."""
    if type(desired) is not bool:
        raise ValueError("consumer target must be boolean")
    kind = expression["kind"]
    if kind in {"any", "all"}:
        conjunction = (kind == "all") == desired
        return {"require": "all" if conjunction else "at_least_one",
                "children": [requirements(child, desired) for child in expression["children"]]}
    if kind == "not":
        return requirements(expression["child"], not desired)
    if kind == "numeric":
        return {"decision_id": expression["decision_id"], "operator": expression["operator"] if desired else NEGATE[expression["operator"]],
                "threshold": expression["threshold"]}
    if kind == "choice":
        return {"decision_id": expression["decision_id"], "membership": "in" if desired else "not_in",
                "options": deepcopy(expression["accepted"])}
    raise ValueError("unknown consumer condition")


def output_guard_contract(case, captured):
    """Audited output adapter binding; other consumers need their own native binding."""
    requests = captured["requests"]
    if len(requests) != 1 or case["callsite"] != "src/output.ts:evaluateOutput/ask":
        raise ValueError("output binding not applicable to this native path")
    questions = requests[0]["request"]["questions"]
    if set(questions) != {"injection", "exfiltration"} or any(q["type"] != "noul" for q in questions.values()):
        raise ValueError("native questions do not match audited output binding")
    threshold = number(captured["native_config"]["security"]["threshold"])
    if threshold != case["config"]["security_threshold"]:
        raise ValueError("native threshold drift")
    expression = {"kind": "any", "children": [
        {"kind": "numeric", "decision_id": f"output:{requests[0]['ordinal']}:{name}",
         "operator": ">=", "threshold": threshold} for name in sorted(questions)]}
    return {"condition": expression, "desired_value": False, "behavior_field": "suspicious",
            "protected_goal": case["trusted_contract"]["protected_goal"],
            "trusted_risk_rule": case["trusted_contract"],
            "evidence": ["src/output.ts:evaluateOutput", "src/output.ts:securityNotice", "native_config.security.threshold"],
            "contract_hash": digest(expression)}
