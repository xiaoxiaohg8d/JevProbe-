"""Stage 5 — Downstream Impact Analysis, layered.

Three explicitly separated divergence layers:
  L1 decision divergence      the judgment output changed (flip)
  L2 behavioral divergence    program control flow / executed actions changed
  L3 security-relevant        the changed behavior reaches a sink classed under
                              the security-impact taxonomy below

Impact taxonomy grounding: InjecAgent harmful-action categories, AgentDojo
attacker-goal framing, CWE-1426 (Improper Validation of Generative AI Output)
plus classic sink CWEs, OWASP LLM Top-10 2025. Jev-ecosystem reality: today's
judgment-gated actions concentrate on approvals, guardrails and tool gating,
so AUTHZ_BYPASS + DANGEROUS_EXECUTION dominate — the taxonomy is extensible
per-repo via SINK_KINDS.
"""
from __future__ import annotations

import ast
from pathlib import Path

SINK_KINDS = [
    (("subprocess", "run"), "command-execution"),
    (("subprocess", "Popen"), "command-execution"),
    (("subprocess", "check_output"), "command-execution"),
    (("os", "system"), "command-execution"),
    (("os", "popen"), "command-execution"),
    (("eval", ""), "code-execution"),
    (("exec", ""), "code-execution"),
    (("write_text", ""), "file-write"),
    (("shutil", "rmtree"), "file-delete"),
    (("requests", "post"), "network-egress"),
    (("requests", "put"), "network-egress"),
    (("socket", "socket"), "network-egress"),
]
NAME_HINTS = {
    "execute": "command-execution", "run_command": "command-execution",
    "shell": "command-execution", "deploy": "deployment",
    "write_file": "file-write", "send": "network-egress", "delete": "file-delete",
}

SECURITY_IMPACT_CLASSES = {
    "AUTHORIZATION_BYPASS": {
        "name": "Authorization / approval bypass",
        "cwe": ["CWE-862", "CWE-863", "CWE-1426"], "owasp": "LLM01:2025",
        "trigger": "guarded action executes without valid authorization (permissive flip)"},
    "PRIVILEGE_ESCALATION": {
        "name": "Privilege boundary crossing",
        "cwe": ["CWE-269", "CWE-250"], "owasp": "LLM01:2025",
        "trigger": "STRICT: only when the run explicitly evidences crossing a privilege "
                   "boundary (e.g. actor scope widens). Never auto-assigned from a mere "
                   "allow/deny flip — that is AUTHORIZATION_BYPASS."},
    "CONFIDENTIALITY_VIOLATION": {
        "name": "Confidentiality violation / data exfiltration",
        "cwe": ["CWE-200", "CWE-359"], "owasp": "LLM02/LLM06:2025",
        "trigger": "gained network-egress sink carries data outward"},
    "INTEGRITY_VIOLATION": {
        "name": "Unauthorized modification of data / configuration",
        "cwe": ["CWE-73", "CWE-284"], "owasp": "LLM01:2025",
        "trigger": "gained file-write / file-delete sink"},
    "DANGEROUS_EXECUTION": {
        "name": "Attacker-influenced command / code execution",
        "cwe": ["CWE-78", "CWE-94", "CWE-1426"], "owasp": "LLM01:2025",
        "trigger": "executed sink consumes attacker-influenced content (here: the request doc)"},
    "AVAILABILITY_VIOLATION": {
        "name": "Denial of legitimate action (restrictive flip)",
        "cwe": ["CWE-400"], "owasp": "LLM01:2025",
        "trigger": "legitimate action blocked by flipping toward the restrictive side"},
    "SECURITY_POLICY_BYPASS": {
        "name": "Security-control verdict bypass (library level)",
        "cwe": ["CWE-1426", "CWE-863"], "owasp": "LLM01:2025",
        "trigger": "permissive security-control flip with observed gated behavior "
                   "and an independently established policy violation; verdict alone "
                   "does not confirm bypass"},
    "DECISION_ONLY": {
        "name": "Decision divergence without behavioral divergence",
        "cwe": ["CWE-1426"], "owasp": "LLM01:2025",
        "trigger": "judgment flipped but downstream control flow did not change"},
}


def _sink_kind(call: ast.Call, funcs: dict) -> tuple[str, str] | None:
    dotted_parts = []
    node = call.func
    while isinstance(node, ast.Attribute):
        dotted_parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        dotted_parts.append(node.id)
    dotted = ".".join(reversed(dotted_parts))

    for (a, b), kind in SINK_KINDS:
        if dotted == a or dotted == f"{a}.{b}":
            return dotted, kind
    leaf = dotted_parts[0] if dotted_parts else ""
    for hint, kind in NAME_HINTS.items():
        if hint in leaf:
            return dotted, f"{kind} (name heuristic)"
    if dotted in funcs:  # one hop into local helper
        fn = funcs[dotted]
        for sub in ast.walk(fn):
            if isinstance(sub, ast.Call):
                hit = _sink_kind(sub, {k: v for k, v in funcs.items() if k != dotted})
                if hit:
                    return f"{dotted} -> {hit[0]}", hit[1]
    return None


def branch_map(source: str, judgment_names: set[str] | None = None) -> list[dict]:
    """Find If branches gated on a judgment result variable and their guarded sinks."""
    from .discovery import dotted_name, is_judgment_leaf
    tree = ast.parse(source)
    funcs = {n.name: n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}

    judge_vars: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            if is_judgment_leaf(dotted_name(node.value.func), judgment_names):
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        judge_vars.add(t.id)

    out = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.If):
            continue
        test_names = {n.id for n in ast.walk(node.test) if isinstance(n, ast.Name)}
        if not (test_names & judge_vars):
            continue
        entry = {"condition": ast.unparse(node.test), "line": node.lineno, "branches": {}}
        for label, body in (("body", node.body), ("else", node.orelse)):
            sinks = []
            for sub in ast.walk(ast.Module(body=body, type_ignores=[])):
                if isinstance(sub, ast.Call):
                    hit = _sink_kind(sub, funcs)
                    if hit:
                        sinks.append({"call": hit[0], "kind": hit[1], "line": sub.lineno})
            entry["branches"][label] = sinks
        out.append(entry)
    return out


def dynamic_divergence(run_with_decision, baseline_decision: str, flipped_decision: str) -> dict:
    """run_with_decision(decision) -> (status, audit). Diff audits across decisions."""
    base_status, base_audit = run_with_decision(baseline_decision)
    flip_status, flip_audit = run_with_decision(flipped_decision)
    base_actions = {(a.get("action"), a.get("cmd")) for a in base_audit}
    flip_actions = {(a.get("action"), a.get("cmd")) for a in flip_audit}
    gained = flip_actions - base_actions
    lost = base_actions - flip_actions
    return {
        "baseline": {"decision": baseline_decision, "status": base_status,
                     "actions": sorted(map(str, base_actions))},
        "flipped": {"decision": flipped_decision, "status": flip_status,
                    "actions": sorted(map(str, flip_actions))},
        "gained_actions": sorted(map(str, gained)),
        "lost_actions": sorted(map(str, lost)),
        "control_flow_diverged": bool(gained or lost or base_status != flip_status),
    }


def classify_divergence(flip: bool, toward_attacker_goal: bool, div: dict | None,
                        static_sink_kinds: set[str] | None = None,
                        security_control: bool = False, *,
                        policy_violation_confirmed: bool = False,
                        authorization_violation: bool = False,
                        attacker_controls_executed_payload: bool = False,
                        legitimate_action_confirmed: bool = False,
                        sensitive_data_confirmed: bool = False,
                        unauthorized_modification_confirmed: bool = False) -> dict:
    """Layered divergence + security-impact classification for one finding.

    static_sink_kinds: sink kinds reachable in the gained branch (static view);
    div: behavioral divergence record (None => not dynamically validated);
    security_control: the judgment is a security control (scanner/guard).
    Evidence flags default false: the caller must establish policy violation,
    authorization state, payload control, sensitive data, or request legitimacy
    before asserting the corresponding security impact. Static sink kinds do
    not prove that a sink was executed or that its payload was unauthorized.
    PRIVILEGE_ESCALATION is NEVER auto-assigned here — it requires explicit
    boundary-crossing evidence supplied by the caller.
    """
    behavioral = bool(div and div.get("control_flow_diverged"))
    gained = _action_names((div or {}).get("gained_actions", []))
    classes: list[str] = []

    # Static sink presence and a flip direction are insufficient to establish
    # an unauthorized action, a data leak, or denial of a legitimate request.
    # Caller-supplied policy/data evidence is required for those stronger claims.
    if flip and not behavioral:
        classes.append("DECISION_ONLY")
    if behavioral and security_control and toward_attacker_goal and gained \
            and policy_violation_confirmed:
        classes.append("SECURITY_POLICY_BYPASS")
    if behavioral and authorization_violation and toward_attacker_goal and gained:
        classes.append("AUTHORIZATION_BYPASS")
    if gained & {"EXECUTE", "DEPLOY"} and attacker_controls_executed_payload:
        classes.append("DANGEROUS_EXECUTION")
    if "SEND" in gained and sensitive_data_confirmed:
        classes.append("CONFIDENTIALITY_VIOLATION")
    if gained & {"WRITE", "DELETE"} and unauthorized_modification_confirmed:
        classes.append("INTEGRITY_VIOLATION")
    if behavioral and _action_names((div or {}).get("lost_actions", [])) \
            and not toward_attacker_goal and legitimate_action_confirmed:
        classes.append("AVAILABILITY_VIOLATION")

    return {
        "decision_divergence": flip,
        "behavioral_divergence": behavioral,
        "security_relevant": any(c != "DECISION_ONLY" for c in classes),
        "impact_classes": classes,
    }


def _action_names(action_strs: list[str]) -> set[str]:
    from ast import literal_eval
    names = set()
    for s in action_strs:
        try:
            v = literal_eval(s)
            if isinstance(v, tuple) and v:
                names.add(str(v[0]))
        except (ValueError, SyntaxError):
            continue
    return names


def impact_stats(findings: list[dict]) -> dict:
    """Aggregate impact-class distribution over classified findings."""
    dist: dict[str, int] = {}
    for f in findings:
        for c in f.get("divergence_layers", {}).get("impact_classes", []):
            dist[c] = dist.get(c, 0) + 1
    return {"n_findings": len(findings), "impact_class_distribution": dist}
