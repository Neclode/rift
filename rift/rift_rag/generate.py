"""Ollama generation client — stdlib only (urllib).

Uses POST /api/generate with qwen2.5-coder:14b and stream=false.
"""

from __future__ import annotations

from .embed import OLLAMA_URL, OllamaError, _post  # reuse the same HTTP plumbing

GEN_MODEL = "qwen2.5-coder:14b"


def generate(prompt: str, model: str = GEN_MODEL) -> str:
    """Run a non-streaming completion and return the response text."""
    resp = _post(
        "/api/generate",
        {"model": model, "prompt": prompt, "stream": False},
    )
    text = resp.get("response")
    if text is None:
        raise OllamaError(
            f"Unexpected generate response from {OLLAMA_URL}: keys={list(resp)}"
        )
    return text


__all__ = ["generate", "GEN_MODEL"]
