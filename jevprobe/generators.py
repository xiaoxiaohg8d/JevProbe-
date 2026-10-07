"""ACT generator backends (attacker-side LLM), selectable via .env.

  ACT_GENERATOR=glm      -> GLM-5.3 via z.ai coding endpoint (quota-limited)
  ACT_GENERATOR=qwen32b  -> local vLLM Qwen3-32B (endpoint configured via environment)

Both implement `rewrite(system, user, temperature, max_tokens) -> str`.
Use a generator model different from the judge model in an experiment.
"""
from __future__ import annotations

import os


def strip_think(text: str) -> str:
    """Qwen3 thinking models may inline <think>...</think>; keep the answer."""
    if "</think>" in text:
        return text.split("</think>", 1)[1].strip()
    return (text or "").strip()


class GLMGenerator:
    name = "glm-5.3"

    def rewrite(self, system: str, user: str, temperature: float, max_tokens: int) -> str:
        from .llm import chat
        return chat(system, user, temperature=temperature, max_tokens=max_tokens)


class LocalVLLMGenerator:
    name = "qwen3-32b"

    def __init__(self, base_url: str | None = None, model: str | None = None):
        from openai import OpenAI, DefaultHttpxClient
        from urllib.parse import urlparse
        self.base_url = base_url or os.getenv(
            "QWEN32B_BASE_URL", "http://127.0.0.1:8332/v1")
        self.model = model or os.getenv("QWEN32B_MODEL", "qwen3-32b")
        local = urlparse(self.base_url).hostname in {"127.0.0.1", "localhost", "::1"}
        self._cli = OpenAI(api_key="none", base_url=self.base_url, max_retries=0,
                           http_client=DefaultHttpxClient(trust_env=not local))

    def rewrite(self, system: str, user: str, temperature: float, max_tokens: int) -> str:
        msgs = [{"role": "system", "content": system}, {"role": "user", "content": user}]
        r = self._cli.chat.completions.create(
            model=self.model, messages=msgs, temperature=temperature,
            max_tokens=max_tokens,
            extra_body={"chat_template_kwargs": {"enable_thinking": False}})
        return strip_think(r.choices[0].message.content or "")


_GENERATORS: dict[str, type] = {"glm": GLMGenerator, "qwen32b": LocalVLLMGenerator}
_active = None


def get_generator():
    """Active ACT generator (singleton), selected by ACT_GENERATOR env."""
    global _active
    if _active is None:
        from pathlib import Path
        from dotenv import load_dotenv
        load_dotenv(Path(__file__).resolve().parents[1] / ".env")  # standalone-safe
        kind = os.getenv("ACT_GENERATOR", "glm").strip().lower()
        if kind not in _GENERATORS:
            raise ValueError(f"unknown ACT_GENERATOR={kind}; "
                             f"available: {sorted(_GENERATORS)}")
        _active = _GENERATORS[kind]()
    return _active
