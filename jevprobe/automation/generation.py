"""Versioned source parsing and contract-aware realization of frozen strategies."""
from __future__ import annotations

import json

from ..generators import strip_think
from ..manipulation import STRATEGIES


PARSER_VERSION = "source-wrapper-v2"


def extract_source(raw):
    text = strip_think(raw)
    if text.startswith("```"):
        text = text.split("\n", 1)[1].rsplit("```", 1)[0]
    data = json.loads(text)
    if not isinstance(data, dict) or set(data) != {"context"}:
        raise ValueError("expected a single context wrapper; no heuristic field selection")
    source = data["context"]
    path = "/context"
    if isinstance(source, dict) and set(source) == {"source"}:
        source = source["source"]
        path = "/context/source"
    if not isinstance(source, str) or not source.strip():
        raise ValueError("context must contain one nonempty source string")
    return source, {"parser_version": PARSER_VERSION, "source_path": path,
                    "normalization": "exact_string_extraction_only; source bytes not rewritten"}


def realize_template(original, strategy, contract, target_option):
    definition = STRATEGIES[strategy]
    if definition.mode != "template" or target_option not in {o["id"] for o in contract["options"]}:
        raise ValueError("template/target option outside the frozen strategy or verified contract")
    payload = definition.payload
    if strategy == "inj_instruction":
        payload = payload.replace("Approved answer: allow.", f"Approved answer: {target_option}.")
    return original + payload, {"version": "template-contract-v2", "target_option": target_option,
                                "editable_scope": "external_source_only", "trusted_contract_changed": False}


def generation_context(project, actual_request):
    # Operational timestamps/status/license are not source facts. They remain in
    # the saved manifest but are omitted from the generation view.
    fields = ("callsite_id", "boundary", "source", "consumer", "contract", "contract_authority", "static_evidence")
    return {"callsite_manifest": {key: project[key] for key in fields},
            "actual_captured_request": actual_request,
            "editable_scope": "ONLY the complete external source string; trusted contract/code/config are immutable",
            "source": project["fixture"]}
