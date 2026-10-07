"""Thin GLM chat client over the OpenAI-compatible coding endpoint."""
from openai import OpenAI

from .config import GLM_API_KEY, GLM_BASE_URL, GLM_MODEL

_client = OpenAI(api_key=GLM_API_KEY, base_url=GLM_BASE_URL)


def chat(system: str, user: str, temperature: float = 0.3, max_tokens: int = 2048) -> str:
    """One chat round. GLM-5.3 is a thinking model: if the budget was consumed
    by reasoning_content and content came back empty, retry once with 4x tokens."""
    msgs = [{"role": "system", "content": system}, {"role": "user", "content": user}]

    def _call(limit: int):
        return _client.chat.completions.create(
            model=GLM_MODEL, messages=msgs, temperature=temperature, max_tokens=limit
        )

    resp = _call(max_tokens)
    content = resp.choices[0].message.content or ""
    if not content.strip() and resp.choices[0].finish_reason == "length":
        resp = _call(max_tokens * 4)
        content = resp.choices[0].message.content or ""
    return content.strip()
