"""Thin wrapper around the local Ollama server (chat with JSON-schema output + embeddings)."""
from __future__ import annotations

import json
import re
import time

from .config import Config


class LLMError(RuntimeError):
    """Recoverable: the model answered, but not usably (e.g. invalid JSON)."""


class LLMTimeout(LLMError):
    """Recoverable: one call took too long (slow model, CPU offload, or runaway generation)."""


class LLMUnavailable(LLMError):
    """Fatal: Ollama is unreachable or a required model is not installed."""


def _field(obj, name, default=None):
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def extract_json(text: str):
    text = (text or "").strip()
    fence = re.search(r"```(?:json)?\s*(.*?)```", text, re.S)
    if fence:
        text = fence.group(1).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        a, b = text.find("{"), text.rfind("}")
        if a != -1 and b > a:
            return json.loads(text[a:b + 1])
        raise


def salvage_findings(text: str):
    """Recover the complete finding objects from a JSON answer that was cut off (token cap / timeout)."""
    m = re.search(r'"findings"\s*:\s*\[', text or "")
    if not m:
        return None
    dec, i, out = json.JSONDecoder(), m.end(), []
    while True:
        while i < len(text) and text[i] in " \n\r\t,":
            i += 1
        if i >= len(text) or text[i] != "{":
            break
        try:
            obj, i = dec.raw_decode(text, i)
        except json.JSONDecodeError:
            break
        out.append(obj)
    return out or None


class OllamaLLM:
    def __init__(self, cfg: Config):
        try:
            import ollama
        except ImportError as e:
            raise LLMUnavailable("The 'ollama' Python package is missing. Run: pip install -r requirements.txt") from e
        self._ollama = ollama
        self.cfg = cfg
        self.client = ollama.Client(host=cfg.host, timeout=cfg.timeout)
        self.stats = {"calls": 0, "prompt_tokens": 0, "output_tokens": 0, "seconds": 0.0, "truncated": 0}
        self.call_log: list[dict] = []

    def _options(self, **extra) -> dict:
        return {"num_ctx": self.cfg.num_ctx, "temperature": self.cfg.temperature, "seed": self.cfg.seed, **extra}

    def _wrap_error(self, e: Exception, model: str) -> LLMError:
        if "timeout" in type(e).__name__.lower() or "timed out" in str(e).lower():
            return LLMTimeout(f"model call timed out after {self.cfg.timeout:.0f}s (model too slow, partly on CPU, or stuck generating)")
        if isinstance(e, self._ollama.ResponseError) and getattr(e, "status_code", None) == 404:
            return LLMUnavailable(f"Model '{model}' is not installed. Run: ollama pull {model}")
        return LLMUnavailable(f"Cannot talk to Ollama at {self.cfg.host} ({type(e).__name__}: {e}). Is `ollama serve` running?")

    # ------------------------------------------------------------------
    def chat_json(self, messages: list[dict], schema: dict | None = None, retries: int = 2, max_tokens: int | None = None) -> dict:
        msgs, fmt = list(messages), (schema or "json")
        for _ in range(retries + 1):
            t0 = time.time()
            try:
                resp = self.client.chat(model=self.cfg.model, messages=msgs, format=fmt,
                                        options=self._options(**({"num_predict": max_tokens} if max_tokens else {})))
            except self._ollama.ResponseError as e:
                if getattr(e, "status_code", None) != 404 and fmt != "json":
                    fmt = "json"          # older server without JSON-schema support: degrade gracefully
                    continue
                raise self._wrap_error(e, self.cfg.model) from e
            except Exception as e:
                raise self._wrap_error(e, self.cfg.model) from e
            dt = time.time() - t0
            pt, ot = _field(resp, "prompt_eval_count", 0) or 0, _field(resp, "eval_count", 0) or 0
            ed = (_field(resp, "eval_duration", 0) or 0) / 1e9
            stop = _field(resp, "done_reason", "") or ""
            self.stats["calls"] += 1
            self.stats["seconds"] += dt
            self.stats["prompt_tokens"] += pt
            self.stats["output_tokens"] += ot
            self.call_log.append({"seconds": round(dt, 1), "prompt_tokens": pt, "output_tokens": ot,
                                  "tok_per_s": round(ot / ed, 1) if ed else None, "stop": stop})
            content = _field(_field(resp, "message"), "content", "") or ""
            try:
                data = extract_json(content)
                if isinstance(data, dict):
                    return data
            except json.JSONDecodeError:
                part = salvage_findings(content)
                if part:                       # keep the complete findings instead of failing the whole window
                    self.stats["truncated"] += 1
                    return {"action": "finish", "findings": part, "_truncated": True}
            msgs += [{"role": "assistant", "content": content},
                     {"role": "user", "content": "That was not valid JSON for the requested schema. Reply again with JSON only."}]
        raise LLMError("model did not return valid JSON after retries")

    def embed(self, texts: list[str]) -> list[list[float]]:
        try:
            resp = self.client.embed(model=self.cfg.embed_model, input=texts)
        except Exception as e:
            raise self._wrap_error(e, self.cfg.embed_model) from e
        vecs = _field(resp, "embeddings")
        if not vecs:
            raise LLMError("empty embedding response")
        return vecs

    def installed_models(self) -> list[str]:
        try:
            resp = self.client.list()
        except Exception as e:
            raise self._wrap_error(e, self.cfg.model) from e
        models = _field(resp, "models", []) or []
        return [(_field(m, "model") or _field(m, "name") or "") for m in models]

    def benchmark(self) -> dict:
        """Tiny generation to measure tokens/second on this machine."""
        t0 = time.time()
        resp = self.client.chat(model=self.cfg.model, messages=[{"role": "user", "content": "Write one sentence about locks."}],
                                options=self._options(num_predict=64))
        n, dur = _field(resp, "eval_count", 0) or 0, (_field(resp, "eval_duration", 0) or 0) / 1e9
        return {"tokens": n, "tok_per_s": round(n / dur, 1) if dur else None, "wall_s": round(time.time() - t0, 1)}

    def loaded_models(self) -> list[dict]:
        """What Ollama currently holds in memory, and how much of it sits on the GPU."""
        try:
            resp = self.client.ps()
        except Exception:
            return []
        out = []
        for m in _field(resp, "models", []) or []:
            size, vram = _field(m, "size", 0) or 0, _field(m, "size_vram", 0) or 0
            out.append({"name": _field(m, "model") or _field(m, "name"), "gpu_pct": round(100 * vram / size) if size else None})
        return out
