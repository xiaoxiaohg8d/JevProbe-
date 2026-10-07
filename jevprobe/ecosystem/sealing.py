"""Read-only verification and mutation guard for completed experiment batches."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


def require_mutable(directory):
    if (Path(directory) / "seal.json").exists():
        raise ValueError("sealed batch is read-only; use verify or a new batch")


def verify_seal(directory):
    root = Path(directory).resolve()
    seal_path = root / "seal.json"
    if not seal_path.exists():
        return {"status": "unsealed", "files": 0}
    seal = json.loads(seal_path.read_text())
    if seal.get("version") != "jevprobe_checksum_seal_v1" or not isinstance(seal.get("files"), dict):
        raise ValueError("unknown checksum seal")
    for relative, expected in seal["files"].items():
        path = (root / relative).resolve()
        if not path.is_relative_to(root) or not path.is_file():
            raise ValueError("sealed file missing or outside batch")
        with path.open("rb") as handle:
            actual = hashlib.file_digest(handle, "sha256").hexdigest()
        if actual != expected:
            raise ValueError("seal checksum mismatch: " + relative)
    files = {str(path.relative_to(root)) for path in root.rglob("*")
             if path.is_file() and "node_modules" not in path.relative_to(root).parts
             and path != seal_path}
    if files != set(seal["files"]):
        raise ValueError("sealed file inventory drift")
    return {"status": "pass", "files": len(files)}
