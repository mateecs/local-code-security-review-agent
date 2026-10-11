"""The security-review agent.

Pipeline:  static leads -> per-window LLM review (RAG context + bounded tool loop)
           -> merge/triage -> deterministic verification -> LLM re-check -> report

The model talks to tools through a JSON "action" protocol enforced with Ollama's
structured outputs, so it does not depend on a model's native tool-calling support.
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field

from .config import Config
from .llm import LLMError, LLMUnavailable
from .prompts import SYSTEM_PROMPT, action_schema, build_user_prompt
from .schema import (SEV_RANK, Candidate, Finding, candidate_to_finding, cwe_group, cwe_id,
                     normalize_severity, same_weakness, REMEDIATION)
from .tools import ToolError, Workspace, neutralize, numbered, scan_static
from .verify import verify_deterministic, verify_llm


class RunCancelled(Exception):
    """Raised from a log callback to abort a run between model calls."""


@dataclass(frozen=True)
class Mode:
    name: str
    use_static: bool = True
    use_llm: bool = True
    use_rag: bool = True
    use_tools: bool = True
    verify: str = "llm"          # none | det | llm


MODES = {m.name: m for m in [
    Mode("static", use_llm=False, use_rag=False, use_tools=False, verify="det"),
    Mode("llm-only", use_static=False, use_rag=False, use_tools=False, verify="det"),
    Mode("llm+static", use_rag=False, use_tools=False, verify="det"),
    Mode("llm+static+rag", use_tools=False, verify="det"),
    Mode("full-noverify", verify="none"),
    Mode("full-det", verify="det"),
    Mode("full"),
]}


@dataclass
class AnalysisResult:
    target: str
    mode: str
    model: str
    findings: list[Finding] = field(default_factory=list)
    candidates: list[Candidate] = field(default_factory=list)
    dropped: list[dict] = field(default_factory=list)      # removed by verification (with reasons)
    rejected: list[dict] = field(default_factory=list)     # static leads the LLM judged false positives
    notes: list[str] = field(default_factory=list)
    stats: dict = field(default_factory=dict)


RISKY_TOKENS = ["execute", "cursor", "subprocess", "os.system", "eval", "exec", "pickle", "yaml.load", "md5", "sha1",
                "debug", "secret", "password", "token", "api_key", "send_file", "open(", "render_template_string",
                "request.args", "request.form", "jwt", "verify=False", "innerHTML", "route", "login", "admin",
                "requests.get", "upload", "random"]
PRIORITY_NAMES = re.compile(r"auth|login|route|view|api|db|model|admin|upload|config|setting|app|main|server|handler", re.I)


class SecurityAgent:
    def __init__(self, cfg: Config, llm, kb, mode: Mode = MODES["full"], log=lambda m: None):
        self.cfg, self.llm, self.kb, self.mode, self.log = cfg, llm, kb, mode, log
        self._tool_calls = 0

    # ------------------------------------------------------------------
    def analyze(self, target: str) -> AnalysisResult:
        t0 = time.time()
        ws = Workspace(target, self.cfg.max_file_bytes)
        res = AnalysisResult(target=str(target), mode=self.mode.name, model=self.cfg.model if self.mode.use_llm else "-")
        calls0 = self.llm.stats["calls"] if self.llm is not None and hasattr(self.llm, "stats") else 0
        self._tool_calls = 0

        if self.mode.use_static:
            res.candidates = scan_static(ws, use_bandit=self.cfg.use_bandit)
            self.log(f"[static] {len(res.candidates)} leads from rules/secrets/AST" + (" (+bandit)" if self.cfg.use_bandit else ""))

        if not self.mode.use_llm:
            findings = [candidate_to_finding(c) for c in res.candidates]
        else:
            findings = self._llm_review(ws, res)

        findings = merge_findings(findings)
        if self.mode.verify in ("det", "llm"):
            findings, dropped = verify_deterministic(findings, ws)
            res.dropped += dropped
            if dropped:
                self.log(f"[verify] dropped {len(dropped)} finding(s) whose evidence is not in the code")
        if self.mode.verify == "llm" and self.mode.use_llm and findings:
            self.log(f"[verify] LLM re-check of {len(findings)} finding(s)")
            try:
                findings, dropped = verify_llm(findings, ws, self.llm, self.kb if self.mode.use_rag else None,
                                               self.cfg.llm_verify_drop_conf, self.log, res.notes, self.cfg.max_tokens_verify)
                res.dropped += dropped
            except LLMUnavailable as e:        # never throw away findings we already have
                res.notes.append(f"LLM re-check aborted: {e}")

        res.findings = sorted(findings, key=lambda f: (SEV_RANK.get(f.severity, 9), -f.confidence, f.file, f.line))
        res.stats = {
            "files_scanned": len(ws.files()), "seconds": round(time.time() - t0, 1),
            "llm_calls": (self.llm.stats["calls"] - calls0) if self.llm is not None and hasattr(self.llm, "stats") else 0,
            "tool_calls": self._tool_calls, "static_leads": len(res.candidates),
        }
        return res

    # ------------------------------------------------------------------
    def _ordered_files(self, ws: Workspace, cands: list[Candidate]) -> list[str]:
        flagged = {c.file for c in cands}
        code = [r for r in ws.rels() if ws.lang(ws.resolve(r)) not in ("text", "json")]
        return sorted(code, key=lambda r: (r not in flagged, not PRIORITY_NAMES.search(r), r))

    def _windows(self, n: int):
        w, o, start = self.cfg.window_lines, self.cfg.window_overlap, 1
        while True:
            end = min(n, start + w - 1)
            yield start, end
            if end >= n:
                return
            start = end - o + 1

    def _rag_blocks(self, code: str, leads: list[Candidate]) -> tuple[list[str], list]:
        """Targeted retrieval: one query per weakness class flagged by the static leads, plus a general query.
        A single whole-window query mixes topics, so the top-k would cover only the loudest one."""
        if not (self.mode.use_rag and self.kb is not None):
            return [], []
        hits, seen = [], set()

        def add(chunks):
            for c in chunks:
                if c.id not in seen and len(hits) < self.cfg.kb_top_k + 2:
                    seen.add(c.id)
                    hits.append(c)

        done = set()
        for l in leads:
            if l.cwe and l.cwe not in done and l.rule_id != "INJECTION-ATTEMPT" and len(done) < 3:
                done.add(l.cwe)
                add(self.kb.search(f"{l.cwe} {l.message}", 1))
        present = [t for t in RISKY_TOKENS if t.lower() in code.lower()]
        add(self.kb.search("security vulnerability review " + " ".join(present), 2))
        return [f"[kb:{h.source}]\n{h.text[:900]}" for h in hits], hits

    def _llm_review(self, ws: Workspace, res: AnalysisResult) -> list[Finding]:
        llm_findings: list[Finding] = []
        rejected: list[tuple[str, int, str]] = []
        files = self._ordered_files(ws, res.candidates)
        if len(files) > self.cfg.max_files:
            res.notes.append(f"{len(files) - len(files[:self.cfg.max_files])} lower-priority file(s) skipped (max_files={self.cfg.max_files})")
            files = files[:self.cfg.max_files]
        for fi, rel in enumerate(files, 1):
            lines = ws.lines(rel)
            for start, end in self._windows(len(lines)):
                leads = [c for c in res.candidates if c.file == rel and start <= c.line <= end]
                code = neutralize(numbered(lines[start - 1:end], start))
                kb_blocks, hits = self._rag_blocks(code, leads)
                lead_txt = [f"line {c.line} [{c.cwe}] {c.rule_id}: {c.message}" for c in leads
                            if c.rule_id != "INJECTION-ATTEMPT"]
                self.log(f"[{fi}/{len(files)}] {rel} lines {start}-{end} ({len(leads)} leads, {len(kb_blocks)} kb chunks)")
                tw = time.time()
                try:
                    found, rej = self._review_window(ws, rel, start, end, len(lines), code, lead_txt, kb_blocks)
                    self.log(f"      done in {time.time() - tw:.0f}s, {len(found)} finding(s)")
                except LLMUnavailable:
                    raise
                except LLMError as e:
                    res.notes.append(f"{rel}:{start}-{end}: LLM review failed, only static leads kept for this window ({e})")
                    self.log(f"      FAILED after {time.time() - tw:.0f}s: {e}")
                    continue
                for f in found:
                    f.kb_sources = [h.source for h in hits if cwe_id(f) and f"cwe-{cwe_id(f)}" in h.source.lower()][:2]
                llm_findings += found
                rejected += [(rel, ln, why) for ln, why in rej]

        # Triage: LLM findings win; static leads the LLM neither confirmed nor rejected are kept.
        out = list(llm_findings)
        twinned: set[int] = set()
        for c in res.candidates:
            if c.rule_id == "INJECTION-ATTEMPT":
                out.append(candidate_to_finding(c))
                continue
            options = [f for f in llm_findings if id(f) not in twinned and f.file == c.file and abs(f.line - c.line) <= 3
                       and same_weakness(cwe_id(f), cwe_id(c))]
            twin = min(options, key=lambda f: abs(f.line - c.line), default=None)   # nearest, one-to-one
            if twin:
                twinned.add(id(twin))
                twin.source = "both"
                twin.confidence = min(1.0, twin.confidence + 0.15)
                continue
            rej = next((r for r in rejected if r[0] == c.file and abs(r[1] - c.line) <= 1), None)
            if rej:
                res.rejected.append({"file": c.file, "line": c.line, "rule": c.rule_id, "reason": rej[2]})
                continue
            out.append(candidate_to_finding(c))
        return out

    # ------------------------------------------------------------------
    def _review_window(self, ws, rel, start, end, total, code, leads, kb_blocks):
        tools = self.mode.use_tools
        allowed = ["read_file", "search_code", "finish"] if tools else ["finish"]
        steps = self.cfg.max_steps if tools else 1
        msgs = [{"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": build_user_prompt(rel, start, end, total, code, leads, kb_blocks, tools)}]
        seen: set[str] = set()
        for step in range(steps):
            last = step == steps - 1
            data = self.llm.chat_json(msgs, action_schema(["finish"] if last else allowed), max_tokens=self.cfg.max_tokens_review)
            action = str(data.get("action", "finish")).lower()
            if action == "finish" or last or action not in allowed:
                return self._parse_findings(data, rel, ws), self._parse_rejections(data)
            key = json.dumps({k: data.get(k) for k in ("action", "path", "start", "end", "pattern")}, sort_keys=True)
            if key in seen:
                msgs += [{"role": "assistant", "content": json.dumps(data)},
                         {"role": "user", "content": "You already requested that. Use action=\"finish\" now."}]
                continue
            seen.add(key)
            try:
                if action == "read_file":
                    out = ws.read_file(str(data.get("path", rel)), data.get("start") or 1, data.get("end"))
                else:
                    out = ws.search_code(str(data.get("pattern", "")))
            except ToolError as e:
                out = f"ERROR: {e}"
            self._tool_calls += 1
            msgs += [{"role": "assistant", "content": json.dumps(data)},
                     {"role": "user", "content": f'<tool_output tool="{action}">\n{neutralize(out)}\n</tool_output>\n'
                                                  'Continue. Use action="finish" when you have enough context.'}]
        return [], []

    def _parse_findings(self, data: dict, default_file: str, ws: Workspace) -> list[Finding]:
        rels = ws.rels()
        out = []
        for raw in (data.get("findings") or [])[:10]:
            if not isinstance(raw, dict) or not str(raw.get("title", "")).strip():
                continue
            file = str(raw.get("file") or default_file)
            if file not in rels:
                base = [r for r in rels if r.endswith("/" + file.split("/")[-1]) or r == file.split("/")[-1]]
                file = base[0] if len(base) == 1 else default_file
            try:
                line = int(raw.get("line") or 0)
            except (TypeError, ValueError):
                line = 0
            try:
                conf = float(raw.get("confidence", 0.5))
            except (TypeError, ValueError):
                conf = 0.5
            conf = conf / 100 if conf > 1 else conf
            cwe = str(raw.get("cwe", "")).strip()
            f = Finding(title=str(raw["title"]).strip()[:140], file=file, line=line,
                        severity=normalize_severity(raw.get("severity")), cwe=cwe,
                        evidence=str(raw.get("evidence", "")), explanation=str(raw.get("explanation", "")),
                        remediation=str(raw.get("remediation", "")), confidence=max(0.0, min(1.0, conf)), source="llm")
            if not f.cwe and cwe_id(f):
                f.cwe = f"CWE-{cwe_id(f)}"
            if not f.remediation:
                f.remediation = REMEDIATION.get(f.cwe, "")
            out.append(f)
        return out

    @staticmethod
    def _parse_rejections(data: dict) -> list[tuple[int, str]]:
        out = []
        for r in data.get("rejected_leads") or []:
            try:
                out.append((int(r.get("line")), str(r.get("reason", ""))[:200]))
            except (TypeError, ValueError, AttributeError):
                continue
        return out


_norm_ev = lambda t: re.sub(r"\s+", " ", re.sub(r"^\s*\d+\|\s?", "", t or "")).strip().lower()


def _is_dup(a: Finding, b: Finding) -> bool:
    """Same weakness, close together, and quoting the same code (adjacent but different lines stay separate)."""
    if a.file != b.file or not same_weakness(cwe_id(a), cwe_id(b)) or abs(a.line - b.line) > 3:
        return False
    ea, eb = _norm_ev(a.evidence), _norm_ev(b.evidence)
    if ea and eb:
        return ea == eb or ea in eb or eb in ea
    return abs(a.line - b.line) <= 1


def merge_findings(findings: list[Finding]) -> list[Finding]:
    """Collapse duplicates (overlapping windows, LLM+static twins) keeping the most confident."""
    out: list[Finding] = []
    for f in sorted(findings, key=lambda x: -x.confidence):
        dup = next((o for o in out if _is_dup(o, f)), None)
        if dup:
            if f.source != dup.source:
                dup.source = "both"
            continue
        out.append(f)
    return out
