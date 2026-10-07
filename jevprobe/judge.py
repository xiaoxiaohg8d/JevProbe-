"""Judge runner: batches decision rows into ONE semif-score pass.

The GPU is selected per invocation by the configured selection policy.
One process launch loads the model once; callers should batch all rows into a
single score() call.
"""
import json
import os
import subprocess
from pathlib import Path

from .config import SEMIF_MODEL, SEMIF_REVISION, SEMIF_SCORE, pick_gpu


def score(rows: list, workdir: Path, tag: str) -> list:
    """Write rows as JSONL, run semif-score, return parsed outputs in input order."""
    workdir.mkdir(parents=True, exist_ok=True)
    inp = workdir / f"{tag}.input.jsonl"
    outp = workdir / f"{tag}.output.jsonl"
    with open(inp, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    if outp.exists():
        outp.unlink()  # semif-score refuses to overwrite existing outputs
    gpu = pick_gpu()
    env = dict(os.environ, CUDA_VISIBLE_DEVICES=gpu)
    subprocess.run(
        [SEMIF_SCORE, "--mode", "direct", "--model", SEMIF_MODEL,
         "--revision", SEMIF_REVISION, "--input", str(inp), "--output", str(outp)],
        check=True, env=env,
    )
    with open(outp, encoding="utf-8") as f:
        results = [json.loads(line) for line in f]
    for r in results:
        r["judge_gpu"] = gpu  # observability: which card actually scored this
    return results
