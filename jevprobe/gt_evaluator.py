"""Sprint 1 GT evaluator: detection precision, typing/sink distributions,
optional confusion vs detector typing, Cohen's kappa for dual annotations.

Semantics (v0, candidate-based): every sample in samples.json is a
detector-flagged call site, so detection PRECISION is computable; RECALL needs
a negative-universe probe (scheduled with Sprint 2) and is reported as null.
"""
from __future__ import annotations

import json
from pathlib import Path

from .schema.annotation import cohen_kappa

GT_DIR = Path(__file__).resolve().parent / "ground_truth"


def load(name: str) -> list[dict] | dict:
    return json.loads((GT_DIR / name).read_text(encoding="utf-8"))


def evaluate(samples: list[dict], annotations: list[dict]) -> dict:
    by_id = {a["sample_id"]: a for a in annotations}
    ann = [by_id[s["sample_id"]] for s in samples if s["sample_id"] in by_id]

    exists = [a["judgment_surface"]["exists"] for a in ann]
    positives = [a for a in ann if a["judgment_surface"]["exists"]]
    precision = sum(exists) / len(exists) if exists else 0.0

    typing_dist: dict[str, int] = {}
    for a in positives:
        t = a["judgment_surface"].get("type") or "untyped"
        typing_dist[t] = typing_dist.get(t, 0) + 1

    source_dist: dict[str, int] = {}
    for a in positives:
        st = (a.get("source") or {}).get("type") or "none"
        source_dist[st] = source_dist.get(st, 0) + 1

    sink_exists = sum(1 for a in positives if (a.get("sink") or {}).get("exists"))
    sink_dist: dict[str, int] = {}
    for a in positives:
        sk = (a.get("sink") or {})
        if sk.get("exists"):
            t = sk.get("type") or "unknown"
            sink_dist[t] = sink_dist.get(t, 0) + 1

    gaps = [a["rationale"] for a in ann
            if "GAP:" in (a.get("rationale") or "")]

    kappa = _kappa_section(annotations)

    return {
        "meta": {"n_samples": len(samples), "n_annotated": len(ann),
                 "annotators": sorted({a.get("annotator", "?") for a in annotations})},
        "detection": {"precision": round(precision, 4),
                      "recall": None,
                      "recall_note": "requires negative-universe probe (Sprint 2)",
                      "positives": sum(exists), "negatives": len(exists) - sum(exists)},
        "typing": {"n": len(positives), "distribution": typing_dist,
                   "confusion_vs_detector": None,
                   "confusion_note": "populated in Sprint 2 when detector typing lands"},
        "source": {"distribution": source_dist},
        "sink": {"exists": sink_exists, "of": len(positives),
                 "distribution": sink_dist},
        "kappa": kappa,
        "taxonomy_gaps": gaps,
    }


def _kappa_section(annotations: list[dict]) -> dict:
    by_annotator: dict[str, dict[str, dict]] = {}
    for a in annotations:
        by_annotator.setdefault(a.get("annotator", "?"), {})[a["sample_id"]] = a
    names = sorted(by_annotator)
    if len(names) < 2:
        return {"overall": None, "per_task": {},
                "note": "second annotator pending (>=20% review required)"}
    a_name, b_name = names[0], names[1]
    shared = sorted(set(by_annotator[a_name]) & set(by_annotator[b_name]))

    def pair(fn):
        return [fn(by_annotator[a_name][i]) for i in shared], \
               [fn(by_annotator[b_name][i]) for i in shared]

    tasks = {
        "detection": lambda a: str(a["judgment_surface"]["exists"]),
        "typing": lambda a: a["judgment_surface"].get("type") or "untyped",
        "sink": lambda a: str((a.get("sink") or {}).get("exists")),
        "source": lambda a: (a.get("source") or {}).get("type") or "none",
    }
    per_task = {}
    disagreements: dict[str, list] = {}
    for t, fn in tasks.items():
        la, lb = pair(fn)
        per_task[t] = round(cohen_kappa(la, lb), 4)
        disagreements[t] = [
            {"sample_id": sid, "A1": fn(by_annotator[a_name][sid]),
             "A2": fn(by_annotator[b_name][sid])}
            for sid in shared
            if fn(by_annotator[a_name][sid]) != fn(by_annotator[b_name][sid])]
    overall = round(sum(per_task.values()) / len(per_task), 4)
    return {"overall": overall, "per_task": per_task, "n_shared": len(shared),
            "disagreements": disagreements}


def main() -> int:
    import sys
    out_name = sys.argv[1] if len(sys.argv) > 1 else "evaluator_report.json"
    samples = load("samples.json")
    annotations = load("annotations.json")
    report = evaluate(samples, annotations)
    (GT_DIR / out_name).write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report["detection"], ensure_ascii=False))
    print(json.dumps(report["kappa"], ensure_ascii=False, indent=1))
    print(f"written: {GT_DIR / out_name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
