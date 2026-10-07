"""Ground-truth annotation schema + evaluator (Sprint 1, 50x4 staged labeling).

Tasks: detection | source | typing | sink. Each label row references a concrete
code location. The evaluator computes precision/recall/F1 over (task, key)
matches; cohen_kappa supports the dual-annotation agreement protocol.
"""
from __future__ import annotations

from dataclasses import dataclass

TASKS = ("detection", "source", "typing", "sink")


@dataclass
class GTLabel:
    task: str            # one of TASKS
    repo: str
    file: str
    line: int
    symbol: str = ""
    label: str = ""      # task-specific: detection: is_jev true/false | typing: surface type | ...
    notes: str = ""

    @property
    def key(self) -> tuple:
        return (self.task, self.repo, self.file, self.line)


def precision_recall_f1(predicted: list[GTLabel], gold: list[GTLabel]) -> dict:
    p_keys = {g.key for g in predicted}
    g_keys = {g.key for g in gold}
    tp = len(p_keys & g_keys)
    precision = tp / len(p_keys) if p_keys else 0.0
    recall = tp / len(g_keys) if g_keys else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {"tp": tp, "precision": round(precision, 4),
            "recall": round(recall, 4), "f1": round(f1, 4)}


def label_agreement(predicted: list[GTLabel], gold: list[GTLabel]) -> dict:
    """Label-level agreement on shared keys (for kappa input and error modes)."""
    gold_by_key = {g.key: g.label for g in gold}
    match = mismatch = missing = 0
    errors: list[dict] = []
    for p in predicted:
        expected = gold_by_key.get(p.key)
        if expected is None:
            missing += 1
        elif expected == p.label:
            match += 1
        else:
            mismatch += 1
            errors.append({"key": list(p.key), "expected": expected, "got": p.label})
    return {"match": match, "mismatch": mismatch, "missing": missing, "errors": errors}


def cohen_kappa(labels_a: list[str], labels_b: list[str]) -> float:
    """Nominal Cohen's kappa for dual annotation on identical item lists."""
    if len(labels_a) != len(labels_b) or not labels_a:
        return 0.0
    n = len(labels_a)
    categories = set(labels_a) | set(labels_b)
    observed = sum(1 for a, b in zip(labels_a, labels_b) if a == b) / n
    a_counts = {c: labels_a.count(c) / n for c in categories}
    b_counts = {c: labels_b.count(c) / n for c in categories}
    expected = sum(a_counts[c] * b_counts[c] for c in categories)
    if expected == 1.0:
        return 1.0
    return (observed - expected) / (1 - expected)
