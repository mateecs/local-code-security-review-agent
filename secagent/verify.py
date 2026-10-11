"""Verification layers that every finding must survive.

Layer 1 (deterministic): the cited file/line must exist and the quoted evidence must
        really appear there. This kills hallucinated findings, which small models produce.
Layer 2 (LLM re-check):  a second, narrower question about the cited snippet only.
"""
from __future__ import annotations

import re
import time

from .llm import LLMError, LLMUnavailable
from .prompts import VERIFY_SCHEMA, VERIFY_SYSTEM
from .schema import Finding, cwe_id
from .tools import ToolError, Workspace, neutralize, numbered

_norm = lambda s: re.sub(r"\s+", " ", re.sub(r"^\s*\d+\|\s?", "", s)).strip().lower()


def verify_deterministic(findings: list[Finding], ws: Workspace) -> tuple[list[Finding], list[dict]]:
    kept, dropped = [], []
    for f in findings:
        def drop(reason):
            dropped.append({"title": f.title, "file": f.file, "line": f.line, "reason": reason, "source": f.source})
        try:
            lines = ws.lines(f.file)
        except ToolError:
            drop("cited file does not exist")
            continue
        ev = [_norm(x) for x in f.evidence.splitlines() if _norm(x)]
        if not ev:
            drop("no evidence quoted")
            continue
        file_norm = [_norm(x) for x in lines]
        lo, hi = max(0, f.line - 4), min(len(lines), f.line + 3)
        if f.line and any(e in l or l in e and len(l) > 8 for e in ev for l in file_norm[lo:hi]):
            f.verified, f.verification = True, "evidence found at cited line"
            kept.append(f)
            continue
        hits = [i + 1 for i, l in enumerate(file_norm) if any(e in l for e in ev)]
        if hits:
            nearest = min(hits, key=lambda h: abs(h - f.line))
            f.verification = f"evidence found at line {nearest} (model cited {f.line}); line corrected"
            f.line, f.verified = nearest, True
            kept.append(f)
        else:
            drop("quoted evidence not found in file (likely hallucination)")
    return kept, dropped


def verify_llm(findings: list[Finding], ws: Workspace, llm, kb, drop_conf: float = 0.8, log=lambda m: None,
               notes: list | None = None, max_tokens: int = 300) -> tuple[list[Finding], list[dict]]:
    kept, dropped, failures = [], [], 0
    for n, f in enumerate(findings):
        if failures >= 2:                      # circuit breaker: the model is struggling, keep the rest unverified
            f.verification = (f.verification + "; " if f.verification else "") + "LLM re-check skipped (model too slow)"
            kept.append(f)
            continue
        log(f"   re-check {n + 1}/{len(findings)}: {f.file}:{f.line} {f.title[:50]}")
        lines = ws.lines(f.file)
        a, b = max(1, f.line - 10), min(len(lines), f.line + 10)
        ref = ""
        if kb is not None:
            hits = [c for c in kb.search(f"{f.title} {f.cwe}", 1)]
            ref = hits[0].text[:900] if hits else ""
        user = (f"Suspected issue: {f.title} ({f.cwe}) at {f.file}:{f.line}\nClaimed evidence: {f.evidence[:300]}\n"
                + (f"\nReference:\n{ref}\n" if ref else "")
                + f'\n<untrusted_code file="{f.file}" lines="{a}-{b}">\n{neutralize(numbered(lines[a - 1:b], a))}\n</untrusted_code>\n'
                "Is this a real, exploitable weakness in this code? Consider sanitisation and authentication visible in the snippet.")
        t0 = time.time()
        try:
            r = llm.chat_json([{"role": "system", "content": VERIFY_SYSTEM}, {"role": "user", "content": user}], VERIFY_SCHEMA,
                              retries=1, max_tokens=max_tokens)
        except LLMUnavailable:
            raise
        except LLMError as e:
            failures += 1
            log(f"      -> failed after {time.time() - t0:.0f}s: {e}")
            if notes is not None:
                notes.append(f"LLM re-check failed for {f.file}:{f.line} ({e})")
            f.verification = (f.verification + "; " if f.verification else "") + f"LLM re-check failed ({e})"
            kept.append(f)
            continue
        failures = 0
        verdict = str(r.get("verdict", "likely")).lower()
        try:
            conf = max(0.0, min(1.0, float(r.get("confidence", 0.5))))
        except (TypeError, ValueError):
            conf = 0.5
        why = str(r.get("reasoning", ""))[:240]
        log(f"      -> {verdict} ({conf:.2f}) in {time.time() - t0:.0f}s")
        if verdict == "safe" and conf >= drop_conf:
            dropped.append({"title": f.title, "file": f.file, "line": f.line, "source": f.source,
                            "reason": f"LLM re-check says safe ({conf:.2f}): {why}"})
            continue
        f.confidence = max(0.05, min(1.0, f.confidence + {"exploitable": 0.15, "likely": 0.0, "unlikely": -0.2, "safe": -0.3}.get(verdict, 0)))
        f.verification = (f.verification + "; " if f.verification else "") + f"LLM re-check: {verdict} ({conf:.2f}) - {why}"
        kept.append(f)
    return kept, dropped
