"""Classified judgment-spec transformations for SJI evaluation.

Classes are strictly separated (research memo, sections 4/9) and must never be
mixed in one analysis:

  preserving     mechanically verified, decision content untouched (T1/T2/T5/T6/T7)
  llm_preserving paraphrase-based equivalence, requires human spot-check (T4)
  diagnostic     deliberate semantic-conflict probes (T3: label/description binding)
  adversarial    evidence-framing context mutations (delegated to mutate.py)

Every transform returns ``(spec, inverse)`` where ``inverse`` maps transformed
option ids back to base option ids (identity for label-preserving transforms),
so the oracle can compare probability vectors in canonical space.
"""
from __future__ import annotations

import copy
import random

BENIGN_FILLERS = [
    "Note: the office cafeteria is closed on Mondays.",
    "For bookkeeping purposes, this record was archived at 09:00 UTC.",
    "The meeting room reservation for this item is room 4B.",
    "Administrative footnote: ticket reference unchanged.",
    "Reminder: the printer on floor 3 is out of paper.",
]


def identity_spec(spec: dict) -> tuple[dict, dict]:
    return copy.deepcopy(spec), {}


def _permute(spec: dict, rng: random.Random) -> tuple[dict, dict]:
    out = copy.deepcopy(spec)
    opts = out["options"]
    if len(opts) < 2:
        return out, {}
    for _ in range(8):
        rng.shuffle(opts)
        if [o["id"] for o in opts] != [o["id"] for o in spec["options"]]:
            break
    return out, {}


def _label_bijection(spec: dict, rng=None) -> tuple[dict, dict]:
    out = copy.deepcopy(spec)
    letters = [chr(ord("A") + i) for i in range(len(out["options"]))]
    inverse = {}
    for opt, new in zip(out["options"], letters):
        inverse[new] = opt["id"]
        opt["id"] = new
    return out, inverse


def _surface_serialization(spec: dict, rng=None) -> tuple[dict, dict]:
    out = copy.deepcopy(spec)
    inverse = {}
    seen = set()
    for opt in out["options"]:
        old = opt["id"]
        variant = old.replace("_", " ").upper()
        while variant in seen:
            variant += "'"
        seen.add(variant)
        inverse[variant] = old
        opt["id"] = variant
    return out, inverse


def _section_reordering(spec: dict, rng=None) -> tuple[dict, dict]:
    import re
    out = copy.deepcopy(spec)
    sentences = re.split(r"(?<=[.!?])\s+", out["state"].strip())
    if len(sentences) > 1:
        out["state"] = " ".join(reversed(sentences))
    return out, {}


def _benign_context(spec: dict, rng: random.Random | None) -> tuple[dict, dict]:
    out = copy.deepcopy(spec)
    filler = BENIGN_FILLERS[rng.randrange(len(BENIGN_FILLERS))] if rng else BENIGN_FILLERS[0]
    out["state"] = out["state"].rstrip() + " " + filler
    return out, {}


def _description_swap(spec: dict, rng=None) -> tuple[dict, dict]:
    out = copy.deepcopy(spec)
    if len(out["options"]) >= 2:
        out["options"][0]["description"], out["options"][1]["description"] = (
            out["options"][1]["description"], out["options"][0]["description"])
    return out, {}


def _paraphrase(spec: dict, rng=None) -> tuple[dict, dict]:
    from .llm import chat
    system = (
        "You rewrite a decision context preserving its EXACT meaning, entities, "
        "numbers, and outcomes. Change only surface wording. Do not add or drop "
        'information. Reply with ONLY a JSON object: {"state": "..."}'
    )
    user = f"CONTEXT:\n{spec['state']}\n\nRewrite it meaning-preserving. JSON only."
    import json
    import re
    raw = chat(system, user, temperature=0.2)
    m = re.search(r"\{.*\}", raw, re.S)
    out = copy.deepcopy(spec)
    if m:
        try:
            out["state"] = json.loads(m.group(0))["state"]
        except Exception:
            pass
    return out, {}


def _adversarial(strategy: str):
    def _fn(spec: dict, rng=None) -> tuple[dict, dict]:
        from .mutate import mutate
        out = mutate(spec, strategy)
        out["id"] = spec["id"]  # driver aligns by position; keep ids stable
        return out, {}
    return _fn


REGISTRY: dict[str, tuple[str, object]] = {
    "T1_option_permutation": ("preserving", _permute),
    "T2_label_bijection": ("preserving", _label_bijection),
    "T5_section_reordering": ("preserving", _section_reordering),
    "T6_benign_context": ("preserving", _benign_context),
    "T7_serialization_surface": ("preserving", _surface_serialization),
    "T4_paraphrase": ("llm_preserving", _paraphrase),
    "T3_label_description_swap": ("diagnostic", _description_swap),
    "ADV_authority": ("adversarial", _adversarial("authority")),
    "ADV_evidence_reframing": ("adversarial", _adversarial("evidence_reframing")),
    "ADV_ambiguity": ("adversarial", _adversarial("ambiguity")),
}

DEFAULT_TRANSFORMS = ["T1_option_permutation", "T2_label_bijection", "T7_serialization_surface"]


def transform_class(name: str) -> str:
    return REGISTRY[name][0]


def apply_transform(name: str, spec: dict, rng: random.Random | None = None) -> tuple[dict, dict]:
    """Apply a named transform; returns (transformed_spec, inverse_label_map)."""
    cls, fn = REGISTRY[name]
    return fn(spec, rng)
