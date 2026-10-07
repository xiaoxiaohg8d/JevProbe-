"""Versioned single-pass entry point, budgeted native measurement and exports."""
from __future__ import annotations

from collections import Counter, defaultdict
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import urllib.request

from dotenv import dotenv_values

from ..automation.runtime import save
from ..automation.store import BudgetExceeded, Store, digest, now
from ..automation.transport import json_request
from ..manipulation import DIMENSIONS
from . import PROTOCOL
from .core import Measurements, case_key, compare, diagnosis, representative
from .native import NativeOutput, offline_response, validate_response
from .review import GemmaReviewer, calibration_samples, calibration_report, pending, PROMPT_VERSION
from .sealing import require_mutable, verify_seal
from .generation_quality import SYSTEM as GENERATOR_SYSTEM, VERSION as GENERATION_VERSION, compose_fragment
from .consumer_plan import output_guard_contract
from .generation_plan import generator_context, VERSION as GENERATION_CONTEXT_VERSION
from ..schema.metrics import uss
from ..schema.taxonomy import TransformationDimension, VisibilityLevel

PROJECT_ROOT = Path(os.environ.get("JEVPROBE_ROOT", Path(__file__).resolve().parents[2]))
ROOT = PROJECT_ROOT
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({})).open
AUTHORIZATION = {
    "id": os.environ.get("JEVPROBE_AUTHORIZATION_ID", "unspecified"),
    "source": os.environ.get("JEVPROBE_AUTHORIZATION_SOURCE", "environment"),
    "note": "authorization metadata is deployment-specific; supply via environment",
}


def file_hash(path):
    with Path(path).open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def tree_hashes(directory):
    base = Path(directory)
    return {str(p.relative_to(base)): file_hash(p) for p in sorted(base.rglob("*"))
            if p.is_file() and not any(x in p.parts for x in ("node_modules", "__pycache__", ".git"))
            and p.name != ".jevprobe_pin.json"}


def framework_version():
    paths = list((ROOT / "jevprobe/ecosystem").glob("*.py")) + list((ROOT / "jevprobe/ecosystem").glob("*.ts"))
    paths += [ROOT / "jevprobe/automation" / name for name in ("store.py", "transport.py", "generation.py", "runtime.py")]
    paths += [ROOT / "jevprobe/manipulation.py", ROOT / "jevprobe/schema/metrics.py", ROOT / "jevprobe/schema/taxonomy.py"]
    return {"head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
            "files": {str(p.relative_to(ROOT)): file_hash(p) for p in sorted(paths)}}

