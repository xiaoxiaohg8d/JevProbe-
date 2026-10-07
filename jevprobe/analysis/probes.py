"""Stage 2 probes as a uniform channel abstraction (M2).

A probe owns one attacker-controllable channel. It can inject a payload
(canary in append mode, or a full replacement in replace mode) into the
channel, and restore the channel afterwards. The shared harness wires a
capturing judge, runs the target once, and checks whether the payload reached
the judgment context.

Local/isolated environments only: HTTP probes serve fixtures or patch the
HTTP client; subprocess probes stub command output. Nothing here may touch
real remote services.
"""
from __future__ import annotations

import copy
import importlib
import json
import subprocess
import sys
from pathlib import Path

from .reachability import load_target, make_canary


class FileSourceProbe:
    kind = "FILE"

    def __init__(self, cfg: dict, target_dir: Path):
        self.path = Path(cfg["path"])
        if not self.path.is_absolute():
            self.path = target_dir / self.path
        self._backup: str | None = None

    def prepare(self, payload: str, mode: str = "append") -> None:
        self._backup = self.path.read_text(encoding="utf-8")
        new = (self._backup + "\n\n" + payload) if mode == "append" else payload
        self.path.write_text(new, encoding="utf-8")

    def restore(self) -> None:
        if self._backup is not None:
            self.path.write_text(self._backup, encoding="utf-8")
            self._backup = None


class _StubResponse:
    status_code = 200
    headers = {}

    def __init__(self, text: str):
        self.text = text

    def json(self):
        return {"content": self.text}

    def raise_for_status(self):
        return None


class HTTPSourceProbe:
    """Patches requests.get / httpx.get to return fixture content (+payload)."""
    kind = "HTTP"

    def __init__(self, cfg: dict, target_dir: Path):
        self.url = cfg.get("url", "http://fixtures.local/")
        fixture = cfg.get("fixture")
        self.base_text = (target_dir / fixture).read_text(encoding="utf-8") if fixture else ""
        self._saved = {}

    def prepare(self, payload: str, mode: str = "append") -> None:
        text = (self.base_text + "\n" + payload) if mode == "append" else payload
        import requests
        self._saved["requests"] = requests.get
        requests.get = lambda url, *a, **kw: _StubResponse(text)
        try:
            import httpx
            self._saved["httpx"] = httpx.get
            httpx.get = lambda url, *a, **kw: _StubResponse(text)
        except ImportError:
            pass

    def restore(self) -> None:
        import requests
        if "requests" in self._saved:
            requests.get = self._saved.pop("requests")
        try:
            import httpx
            if "httpx" in self._saved:
                httpx.get = self._saved.pop("httpx")
        except ImportError:
            pass


class SubprocessSourceProbe:
    """Patches subprocess.check_output/run to return fixture stdout (+payload)."""
    kind = "SUBPROCESS"

    def __init__(self, cfg: dict, target_dir: Path):
        self.hint = cfg.get("hint", "")
        fixture = cfg.get("fixture")
        self.base_text = (target_dir / fixture).read_text(encoding="utf-8") if fixture else ""
        self._saved = {}

    def prepare(self, payload: str, mode: str = "append") -> None:
        text = (self.base_text + "\n" + payload) if mode == "append" else payload
        encoded = text.encode()

        def fake_check_output(cmd, *a, **kw):
            kw.pop("input", None)
            return encoded

        def fake_run(cmd, *a, **kw):
            kw.pop("input", None)
            return subprocess.CompletedProcess(cmd, 0, stdout=encoded, stderr=b"")

        self._saved = {"subprocess.check_output": subprocess.check_output,
                       "subprocess.run": subprocess.run}
        subprocess.check_output = fake_check_output
        subprocess.run = fake_run

    def restore(self) -> None:
        for name, fn in self._saved.items():
            setattr(subprocess, name.split(".", 1)[1], fn)
        self._saved = {}


class HarnessEnv:
    """Fixture stubs for ALL in-harness executions of a target.

    Serves declared fixture content for HTTP and SUBPROCESS channels so that
    target runs never touch real remote services — even when no canary probe
    is active (differential runs, e2e runs, counterfactual replays). Canary
    probes layer their payload patch ON TOP of these stubs.
    """

    def __init__(self, target_dir: Path):
        self.target_dir = target_dir
        self.manifest = target_dir / "sources.json"
        self._saved: dict[str, object] = {}

    def __enter__(self):
        if not self.manifest.exists():
            return self
        texts: dict[str, str] = {}
        for c in json.loads(self.manifest.read_text(encoding="utf-8")):
            fx = c.get("fixture")
            if fx:
                try:
                    texts[c.get("kind", "").upper()] = \
                        (self.target_dir / fx).read_text(encoding="utf-8")
                except OSError:
                    continue
        import requests
        self._saved["requests.get"] = requests.get
        requests.get = lambda url, *a, **kw: _StubResponse(texts.get("HTTP", ""))
        try:
            import httpx
            self._saved["httpx.get"] = httpx.get
            httpx.get = lambda url, *a, **kw: _StubResponse(texts.get("HTTP", ""))
        except ImportError:
            pass
        if "SUBPROCESS" in texts:
            enc = texts["SUBPROCESS"].encode()

            def fake_co(cmd, *a, **kw):
                kw.pop("input", None)
                return enc

            import subprocess as sp
            self._saved["subprocess.check_output"] = sp.check_output
            sp.check_output = fake_co
        return self

    def __exit__(self, *exc):
        import requests
        import subprocess as sp
        mods = {"requests": requests, "httpx": sys.modules.get("httpx"), "subprocess": sp}
        for key, fn in list(self._saved.items()):
            mod_name, attr = key.split(".", 1)
            mod = mods.get(mod_name)
            if mod is not None:
                setattr(mod, attr, fn)
            self._saved.pop(key)
        return False


PROBES = {p.kind: p for p in (FileSourceProbe, HTTPSourceProbe, SubprocessSourceProbe)}


def build_probe(cfg: dict, target_dir: Path):
    kind = cfg.get("kind", "").upper()
    if kind not in PROBES:
        return None
    return PROBES[kind](cfg, target_dir)


def validate_source(cfg: dict, target_dir: Path, entry_module: str) -> dict:
    """Canary-validate one declared source channel; returns a status record."""
    report = {"source_id": cfg.get("id", "?"), "kind": cfg.get("kind", "?"),
              "detail": cfg.get("path") or cfg.get("url") or cfg.get("hint", ""),
              "status": "ERROR", "canary_reached": False}
    probe = build_probe(cfg, target_dir)
    if probe is None:
        report["status"] = "UNSUPPORTED"
        return report

    sys.path.insert(0, str(target_dir))
    judge_client = importlib.import_module("judge_client")
    captured: list[dict] = []
    real = judge_client.judge

    def capturing_judge(spec):
        captured.append(copy.deepcopy(spec))
        try:
            return real(spec)
        except NotImplementedError:
            return "deny"

    canary = make_canary()
    try:
        with HarnessEnv(target_dir):
            probe.prepare(canary, mode="append")
            judge_client.judge = capturing_judge
            target = load_target(target_dir, entry_module)
            audit: list = []
            run_arg = cfg.get("run_arg") or str(_first_run_arg(cfg, target_dir))
            if not Path(run_arg).is_absolute():
                run_arg = str(target_dir / run_arg)
            target.run(run_arg, audit)
            probe.restore()
        states = [c.get("state", "") for c in captured]
        report.update({
            "canary": canary,
            "judgment_invocations": len(captured),
            "canary_reached": any(canary in s for s in states),
            "captured_spec": captured[0] if captured else None,
        })
        report["status"] = "VERIFIED" if report["canary_reached"] else "NOT_REACHED"
    except Exception as e:
        report["error"] = str(e)[:200]
        report["status"] = "ERROR"
    finally:
        judge_client.judge = real
        probe.restore()
        sys.path.remove(str(target_dir))
    return report


def _first_run_arg(cfg: dict, target_dir: Path) -> str:
    """Raw (possibly relative) run argument for target.run()."""
    return cfg.get("path") or "data/request.json"


def enumerate_sources(manifest_path: Path, target_dir: Path, entry_module: str) -> list[dict]:
    """Validate every declared source; only VERIFIED ones may feed Stage 3."""
    cfgs = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    return [validate_source(c, target_dir, entry_module) for c in cfgs]
