"""Callsite identity, static evidence, selection and immutable configuration."""
from __future__ import annotations

import ast
import json
from pathlib import Path
import subprocess

from .store import digest
from ..schema.taxonomy import SourceType, SurfaceType, InjectionLocation
from ..manipulation import STRATEGIES


CATEGORIES = ("Agent framework", "Coding agent", "MCP/tool agent", "Security agent", "Other")


def snapshot(root, files):
    from ..analysis.native_e2e import fingerprint
    return fingerprint(Path(root), files)


def static_contract(root, file, symbol):
    path = Path(root) / file
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    matches = [node for node in ast.walk(tree)
               if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == symbol]
    if len(matches) != 1:
        raise ValueError(f"ambiguous/missing actual symbol: {file}:{symbol}")
    fn = matches[0]
    calls = sorted({ast.unparse(node.func) for node in ast.walk(fn) if isinstance(node, ast.Call)})
    branches = [{"line": node.lineno, "condition": ast.unparse(node.test)}
                for node in ast.walk(fn) if isinstance(node, ast.If)]
    return {"file": file, "symbol": symbol, "line": fn.lineno, "end_line": fn.end_lineno,
            "source_hash": digest(source), "function_source": ast.get_source_segment(source, fn),
            "calls": calls, "branches": branches, "status": "static_candidate",
            "limitations": "AST-local evidence; not a complete cross-module call graph"}


def callsite_id(project):
    # Wrappers do not introduce new identities unless source/consumer/contract differ.
    identity = {k: project[k] for k in ("repo_id", "boundary", "source", "consumer", "contract")}
    return "CS-" + digest(identity)[:20]


def validate_manifest(manifest):
    if manifest.get("version") != "s13.1" or manifest.get("trials_per_side") != 5:
        raise ValueError("s13.1 uses frozen default 5+5 trials")
    projects = manifest["projects"]
    if not projects or len(projects) > 3 or len({p["repo_id"] for p in projects}) != len(projects):
        raise ValueError("first batch requires 1..3 distinct projects")
    if manifest.get("judge_model") != "jev-1.13.0":
        raise ValueError("main judge model is frozen")
    count = 0
    for project in projects:
        exclusion = repository_exclusion(project)
        if exclusion:
            raise ValueError(f"project excluded by repository metadata: {exclusion}")
        if project["category"] not in CATEGORIES or project["surface_type"] not in SurfaceType.values():
            raise ValueError("invalid category/surface")
        if project["source"]["type"] not in SourceType.values() or project["source"]["location"] not in InjectionLocation.values():
            raise ValueError("invalid frozen source/location")
        if project["surface_type"] != "choice":
            raise ValueError("adapter has no support for this surface; record coverage gap")
        if len(project["strategies"]) > 5 or len(set(project["strategies"])) != len(project["strategies"]):
            raise ValueError("maximum five unique transformations/project")
        if not set(project["strategies"]) <= STRATEGIES.keys():
            raise ValueError("unfrozen strategy")
        if project["callsite_id"] != callsite_id(project):
            raise ValueError("callsite identity mismatch")
        if project["deployment"] not in {"jev_substitute", "default_other", "native_jev", "deterministic_control"}:
            raise ValueError("deployment layer required")
        if project["target"]["dirty"]:
            raise ValueError("target has existing modifications; provenance unresolved")
        count += len(project["strategies"])
    if count > 15:
        raise ValueError("first-batch quota exceeded")
    return manifest


def repository_exclusion(record):
    """Apply declared repository status consistently to scheduling and admission."""
    for key in ("disabled", "fork", "archived"):
        if record.get(key):
            return key
    return None


def merge_repository_metadata(records, snapshots, categories=None):
    """Prefer captured GitHub metadata over historical candidate attributes.

    snapshots maps requested names to {response, snapshot_at, attempt_id}. Keep
    the old record, snapshot date and HTTP lineage; this does not fetch data.
    Metadata-only repositories are appended when a declared category is given;
    their provenance explicitly separates them from the historical query set.
    """
    lookup = {}
    for requested, item in snapshots.items():
        lookup[requested.casefold()] = item
        lookup[item["response"]["full_name"].casefold()] = item
    source_records = list(records)
    names = {row["repo"].casefold() for row in source_records}
    categories = {name.casefold(): value for name, value in (categories or {}).items()}
    for requested, item in snapshots.items():
        info = item["response"]
        category = categories.get(info["full_name"].casefold(), categories.get(requested.casefold()))
        if requested.casefold() not in names and info["full_name"].casefold() not in names and category in CATEGORIES:
            source_records.append({"repo": info["full_name"], "category": category,
                                   "stars": info["stargazers_count"],
                                   "provenance": "metadata_only_not_in_historical_query_population"})
            names.add(info["full_name"].casefold())
    output = []
    for row in source_records:
        record = dict(row)
        item = lookup.get(row["repo"].casefold())
        if item:
            info = item["response"]
            record.update(repo=info["full_name"], github_id=info["id"],
                          stars=info["stargazers_count"], source_url=info["html_url"],
                          fork=info["fork"], archived=info["archived"], disabled=info["disabled"],
                          license=info.get("license"),
                          metadata_provenance={"prior_record": dict(row), "snapshot_at": item["snapshot_at"],
                                               "attempt_id": item["attempt_id"]})
        output.append(record)
    return output


def select_candidates(records, eligibility=None):
    """Keep every candidate and exclusion; sort within strata, dedupe identity/families.

    This is a schedule, not a census of confirmed surfaces. Missing eligibility
    stays untested. Forks and declared code families have explicit exclusions.
    """
    eligibility = eligibility or {}
    seen, families, output = set(), set(), []
    for row in sorted(records, key=lambda r: (CATEGORIES.index(r["category"]), -r["stars"], r["repo"].casefold())):
        record = dict(row)
        identity = str(row.get("github_id") or row["repo"].casefold())
        family = row.get("code_family")
        if identity in seen:
            reason = "duplicate_repository"
        elif repository_exclusion(row):
            reason = repository_exclusion(row)
        elif family and family in families:
            reason = "duplicate_code_family"
        else:
            reason = eligibility.get(row["repo"], "untested")
        seen.add(identity)
        if family:
            families.add(family)
        record["selection_status"] = reason
        output.append(record)
    return output
