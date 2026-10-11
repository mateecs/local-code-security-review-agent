"""Render an AnalysisResult as Markdown, JSON or SARIF 2.1.0."""
from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import asdict
from datetime import datetime

from . import __version__
from .agent import AnalysisResult
from .schema import SEVERITIES, cwe_id

_SECRET_VALUE = re.compile(r"""(["'])([^"'\n]{9,})\1""")


def redact(text: str, cwe: str) -> str:
    """Never echo full secrets back into reports."""
    if cwe_id(type("X", (), {"cwe": cwe, "title": ""})) != "798":
        return text
    return _SECRET_VALUE.sub(lambda m: f"{m.group(1)}{m.group(2)[:4]}***{m.group(1)}", text)


def to_json(res: AnalysisResult) -> str:
    return json.dumps({
        "target": res.target, "mode": res.mode, "model": res.model, "stats": res.stats, "notes": res.notes,
        "findings": [{**f.to_dict(), "evidence": redact(f.evidence, f.cwe)} for f in res.findings],
        "static_leads": [asdict(c) for c in res.candidates], "dropped_by_verification": res.dropped, "static_leads_rejected_by_llm": res.rejected,
    }, indent=2)


def to_sarif(res: AnalysisResult) -> str:
    level = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
    rules, results = {}, []
    for f in res.findings:
        rid = f"CWE-{cwe_id(f)}" if cwe_id(f) else "secagent"
        rules.setdefault(rid, {"id": rid, "shortDescription": {"text": f.title}})
        results.append({
            "ruleId": rid, "level": level.get(f.severity, "warning"),
            "message": {"text": f"{f.title}. {f.explanation} Fix: {f.remediation}".strip()},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.file}, "region": {"startLine": max(1, f.line)}}}],
            "properties": {"confidence": f.confidence, "source": f.source, "verified": f.verified},
        })
    return json.dumps({
        "version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{"tool": {"driver": {"name": "secagent", "version": __version__, "rules": list(rules.values())}}, "results": results}],
    }, indent=2)


def to_markdown(res: AnalysisResult) -> str:
    sev = Counter(f.severity for f in res.findings)
    L = [f"# Security review: `{res.target}`", "",
         f"- Mode: `{res.mode}` | Model: `{res.model}` | Generated: {datetime.now():%Y-%m-%d %H:%M}",
         f"- Files scanned: {res.stats.get('files_scanned')} | LLM calls: {res.stats.get('llm_calls')} | "
         f"Tool calls: {res.stats.get('tool_calls')} | Time: {res.stats.get('seconds')}s",
         "- Summary: " + (", ".join(f"{sev[s]} {s}" for s in SEVERITIES if sev[s]) or "no findings"), ""]
    if res.findings:
        L += ["| # | Severity | CWE | Location | Finding | Source | Verified | Conf. |", "|---|---|---|---|---|---|---|---|"]
        for i, f in enumerate(res.findings, 1):
            L.append(f"| {i} | {f.severity} | {f.cwe or '-'} | `{f.file}:{f.line}` | {f.title} | {f.source} | "
                     f"{'yes' if f.verified else 'no'} | {f.confidence:.2f} |")
        L.append("")
    for i, f in enumerate(res.findings, 1):
        L += [f"## {i}. {f.title}", f"**{f.severity.upper()}** | {f.cwe or 'CWE n/a'} | `{f.file}:{f.line}` | source: {f.source} | confidence {f.confidence:.2f}", ""]
        if f.evidence:
            L += ["```", redact(f.evidence.strip(), f.cwe), "```"]
        if f.explanation:
            L += [f"**Why it matters:** {f.explanation}", ""]
        if f.remediation:
            L += [f"**Fix:** {f.remediation}", ""]
        if f.verification:
            L += [f"**Verification:** {f.verification}", ""]
        if f.kb_sources:
            L += ["**Knowledge base:** " + ", ".join(f"`{s}`" for s in f.kb_sources), ""]
    if res.dropped:
        L += ["## Removed by verification", "These were proposed but did not survive checking against the actual code.", ""]
        L += [f"- `{d['file']}:{d['line']}` {d['title']} ({d['source']}): {d['reason']}" for d in res.dropped] + [""]
    if res.rejected:
        L += ["## Static leads rejected by the LLM", ""]
        L += [f"- `{r['file']}:{r['line']}` {r['rule']}: {r['reason']}" for r in res.rejected] + [""]
    if res.notes:
        L += ["## Notes", ""] + [f"- {n}" for n in res.notes] + [""]
    return "\n".join(L)
