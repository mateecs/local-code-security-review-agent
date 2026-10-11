"""Streamlit front end for secagent.   Run:  streamlit run ui.py

Pick a project folder, run a review with live logs, inspect findings with code context,
compare runs and run the evaluation harness. Everything stays local.
"""
from __future__ import annotations

import json
import subprocess
import sys
import threading
import time
import traceback
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

import pandas as pd
import streamlit as st

from secagent import evaluate
from secagent.agent import MODES, RunCancelled, SecurityAgent
from secagent.config import ROOT, Config
from secagent.llm import LLMUnavailable, OllamaLLM
from secagent.rag import KnowledgeBase
from secagent.report import to_json, to_markdown, to_sarif
from secagent.schema import SEVERITIES
from secagent.tools import ToolError, Workspace

st.set_page_config(page_title="secagent", page_icon="🛡️", layout="wide")

SEV_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
MODE_ORDER = ["full-det", "full", "static", "llm+static+rag", "llm+static", "llm-only", "full-noverify"]
MODE_HELP = {
    "full-det": "Recommended first run: static leads + knowledge base + tool loop; findings must quote real code.",
    "full": "Everything, plus an LLM re-check of every finding (most thorough, slowest).",
    "static": "Rules, secrets, AST (+Bandit). No model needed, takes seconds. Your baseline.",
    "llm+static+rag": "Model + static leads + knowledge base, no tool loop.",
    "llm+static": "Model + static leads (ablation: no knowledge base).",
    "llm-only": "Bare model, no hints at all (ablation baseline).",
    "full-noverify": "Everything without verification (ablation: shows what verification removes).",
}


# ----------------------------------------------------------------------------
# Background jobs (the UI polls them, so reruns never kill a running review)
# ----------------------------------------------------------------------------
@dataclass
class Job:
    kind: str
    label: str
    started: float = field(default_factory=time.time)
    logs: list = field(default_factory=list)
    result: object = None
    error: str | None = None
    done: bool = False
    out_dir: Path | None = None
    llm_calls: list = field(default_factory=list)
    cancel: threading.Event = field(default_factory=threading.Event)

    def log(self, msg) -> None:
        if self.cancel.is_set():
            raise RunCancelled()
        self.logs.append((round(time.time() - self.started, 1), str(msg)))

    def log_text(self) -> str:
        return "\n".join(f"[{t:7.1f}s] {m}" for t, m in self.logs)


def make_cfg(p: dict) -> Config:
    cfg = Config()
    cfg.model, cfg.embed_model = p["model"], p["embed_model"]
    cfg.num_ctx, cfg.timeout = int(p["ctx"]), float(p["timeout"])
    cfg.window_lines, cfg.max_files, cfg.use_bandit = int(p["window"]), int(p["max_files"]), bool(p["bandit"])
    return cfg


def run_analyze(job: Job, p: dict) -> None:
    try:
        cfg, mode = make_cfg(p), MODES[p["mode"]]
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        job.out_dir = ROOT / "reports" / f"{Path(p['path']).resolve().name}-{mode.name}-{stamp}"
        job.out_dir.mkdir(parents=True, exist_ok=True)
        job.log(f"Target: {p['path']} | mode: {mode.name} | model: {cfg.model if mode.use_llm else '(no model)'} | "
                f"ctx {cfg.num_ctx} | window {cfg.window_lines} lines | timeout {cfg.timeout:.0f}s")
        llm = OllamaLLM(cfg) if mode.use_llm else None
        kb = KnowledgeBase(cfg, llm, log=job.log).load_or_build() if mode.use_rag else None
        res = SecurityAgent(cfg, llm, kb, mode, log=job.log).analyze(p["path"])
        job.result, job.llm_calls = res, list(getattr(llm, "call_log", []))
        (job.out_dir / "report.md").write_text(to_markdown(res), encoding="utf-8")
        (job.out_dir / "findings.json").write_text(to_json(res), encoding="utf-8")
        (job.out_dir / "report.sarif").write_text(to_sarif(res), encoding="utf-8")
        job.log(f"Done: {len(res.findings)} finding(s), {len(res.dropped)} removed by verification, {res.stats['seconds']}s")
    except RunCancelled:
        job.error = "Run cancelled. (Stop takes effect after the current model call finishes.)"
    except LLMUnavailable as e:
        job.error = f"{e}\n\nTry the 'static' mode (no model needed) or check Ollama in the sidebar."
    except Exception:
        job.error = traceback.format_exc()
    finally:
        job.done = True
        if job.out_dir and job.out_dir.exists():
            (job.out_dir / "run.log").write_text(job.log_text() + (f"\nERROR: {job.error}" if job.error else ""), encoding="utf-8")


def run_eval_job(job: Job, p: dict, modes: list[str]) -> None:
    try:
        cfg = make_cfg(p)
        need_llm = any(MODES[m].use_llm for m in modes)
        llm = OllamaLLM(cfg) if need_llm else None
        kb = KnowledgeBase(cfg, llm, log=job.log).load_or_build() if any(MODES[m].use_rag for m in modes) else None
        job.log(f"Evaluating modes {modes} with model {cfg.model if need_llm else '(none)'}")
        report = evaluate.run_eval(cfg, llm, kb, modes, log=job.log)
        evaluate.save(report)
        job.result = report
        job.log("Evaluation finished; saved to eval/results/")
    except RunCancelled:
        job.error = "Evaluation cancelled."
    except LLMUnavailable as e:
        job.error = str(e)
    except Exception:
        job.error = traceback.format_exc()
    finally:
        job.done = True


def start(kind: str, label: str, fn, *args) -> None:
    job = Job(kind, label)
    threading.Thread(target=fn, args=(job, *args), daemon=True).start()
    st.session_state.job = job


# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------
def browse_folder() -> None:
    """Native folder dialog, run in a subprocess (tkinter misbehaves inside Streamlit threads)."""
    code = ("import tkinter as tk\nfrom tkinter import filedialog\nr = tk.Tk(); r.withdraw(); r.attributes('-topmost', True)\n"
            "print(filedialog.askdirectory(title='Select the project folder to review'))")
    try:
        out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=300)
        if out.stdout.strip():
            st.session_state.path = str(Path(out.stdout.strip()))
        elif out.returncode != 0:
            st.session_state.browse_error = "Folder dialog unavailable (tkinter missing?). Paste the path instead."
    except Exception as e:
        st.session_state.browse_error = f"Folder dialog failed: {e}. Paste the path instead."


def refresh_ollama(cfg_hint: Config) -> None:
    info = {"ok": False, "models": [], "loaded": [], "error": "", "ts": time.time()}
    try:
        llm = OllamaLLM(cfg_hint)
        info["models"], info["loaded"], info["ok"] = llm.installed_models(), llm.loaded_models(), True
    except Exception as e:
        info["error"] = str(e)
    st.session_state.ollama = info


def view_from_result(res) -> dict:
    d = json.loads(to_json(res))
    d["static_leads"] = [asdict(c) for c in res.candidates]
    return d


def context_snippet(view: dict, f: dict, radius: int = 6) -> str:
    try:
        ws = Workspace(view["target"])
        lines = ws.lines(f["file"])
    except Exception:
        return ""
    a, b = max(1, f["line"] - radius), min(len(lines), f["line"] + radius)
    return "\n".join(f"{'>>' if i == f['line'] else '  '} {i:4d} | {lines[i - 1]}" for i in range(a, b + 1))


def render_view(view: dict, logs_text: str = "", llm_calls: list | None = None, out_dir: Path | None = None, key: str = "") -> None:
    findings, stats = view.get("findings", []), view.get("stats", {})
    sev = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITIES}
    c = st.columns(6)
    c[0].metric("Findings", len(findings))
    c[1].metric("Critical / High", sev["critical"] + sev["high"])
    c[2].metric("Verified", sum(1 for f in findings if f.get("verified")))
    c[3].metric("Removed by verification", len(view.get("dropped_by_verification", [])))
    c[4].metric("LLM calls", stats.get("llm_calls", 0))
    c[5].metric("Time", f"{stats.get('seconds', 0)}s")
    for n in view.get("notes", []):
        st.warning(n)

    tabs = st.tabs(["Findings", "Logs", "Verification", "Static leads", "Model calls", "Downloads"])
    with tabs[0]:
        if not findings:
            st.success("No findings reported.")
        else:
            f1, f2, f3 = st.columns([2, 2, 1])
            sev_sel = f1.multiselect("Severity", SEVERITIES, default=SEVERITIES, key=f"sev{key}")
            src_sel = f2.multiselect("Source", ["llm", "static", "both"], default=["llm", "static", "both"], key=f"src{key}")
            only_ver = f3.checkbox("Verified only", key=f"ver{key}")
            shown = [f for f in findings if f["severity"] in sev_sel and f["source"] in src_sel and (f.get("verified") or not only_ver)]
            df = pd.DataFrame([{"Sev": f"{SEV_ICON.get(f['severity'], '')} {f['severity']}", "CWE": f["cwe"] or "-",
                                "Location": f"{f['file']}:{f['line']}", "Finding": f["title"], "Source": f["source"],
                                "Verified": bool(f.get("verified")), "Conf.": round(f["confidence"], 2)} for f in shown])
            st.dataframe(df, hide_index=True)
            for f in shown:
                with st.expander(f"{SEV_ICON.get(f['severity'], '')} {f['file']}:{f['line']}  -  {f['title']}"):
                    st.caption(f"{f['severity'].upper()} | {f['cwe'] or 'CWE n/a'} | source: {f['source']} | "
                               f"confidence {f['confidence']:.2f} | verified: {f.get('verified')}")
                    ctx = context_snippet(view, f)
                    if ctx:
                        st.code(ctx, language="python")
                    elif f.get("evidence"):
                        st.code(f["evidence"])
                    if f.get("explanation"):
                        st.markdown(f"**Why it matters:** {f['explanation']}")
                    if f.get("remediation"):
                        st.markdown(f"**Fix:** {f['remediation']}")
                    if f.get("verification"):
                        st.markdown(f"**Verification:** {f['verification']}")
                    if f.get("kb_sources"):
                        st.markdown("**Knowledge base:** " + ", ".join(f"`{s}`" for s in f["kb_sources"]))
    with tabs[1]:
        st.code(logs_text or "(no log stored for this run)", language="text")
    with tabs[2]:
        st.caption("Proposed but rejected: the quoted evidence was not in the code, or the LLM re-check judged it safe.")
        d = view.get("dropped_by_verification", [])
        if d:
            st.dataframe(pd.DataFrame(d), hide_index=True)
        else:
            st.info("Nothing was removed.")
        r = view.get("static_leads_rejected_by_llm", [])
        if r:
            st.caption("Static leads the LLM judged to be false positives:")
            st.dataframe(pd.DataFrame(r), hide_index=True)
    with tabs[3]:
        leads = view.get("static_leads", [])
        if leads:
            st.dataframe(pd.DataFrame(leads), hide_index=True)
        else:
            st.info("No static leads (or static analysis was off).")
    with tabs[4]:
        if llm_calls:
            cdf = pd.DataFrame(llm_calls)
            cdf.index = cdf.index + 1
            st.dataframe(cdf)
            st.caption(f"Average {cdf['seconds'].mean():.1f}s per call, median {cdf['tok_per_s'].median()} tokens/s. "
                       "Calls ending with stop='length' hit the output cap.")
            st.bar_chart(cdf["seconds"])
        else:
            st.info("No model calls recorded for this run.")
    with tabs[5]:
        if out_dir and out_dir.exists():
            st.caption(f"Saved in `{out_dir}`")
            for name, mime in [("report.md", "text/markdown"), ("findings.json", "application/json"),
                               ("report.sarif", "application/json"), ("run.log", "text/plain")]:
                p = out_dir / name
                if p.exists():
                    st.download_button(f"Download {name}", p.read_bytes(), file_name=name, mime=mime, key=f"dl{key}{name}")
        else:
            st.info("Reports are written when a run finishes.")


# ----------------------------------------------------------------------------
# Sidebar: Ollama status + settings
# ----------------------------------------------------------------------------
job: Job | None = st.session_state.get("job")
running = bool(job and not job.done)
base = Config()
if "ollama" not in st.session_state:
    refresh_ollama(base)

with st.sidebar:
    st.title("🛡️ secagent")
    page = st.radio("Page", ["Review a project", "Evaluation", "History"], disabled=running)
    st.divider()
    ol = st.session_state.ollama
    if ol["ok"]:
        st.success(f"Ollama connected ({len(ol['models'])} models)")
        for m in ol["loaded"]:
            pct = m["gpu_pct"]
            if pct in (None, 100):
                st.caption(f"Loaded: {m['name']} ({pct}% on GPU)")
            else:
                st.warning(f"Loaded: {m['name']} ({pct}% on GPU: partly on CPU, so calls will be slow; try a smaller context)")
    else:
        st.error("Ollama not reachable")
        st.caption(ol["error"][:200])
    if st.button("Refresh Ollama status", disabled=running):
        refresh_ollama(base)
        st.rerun()

    chat_models = [m for m in ol["models"] if "embed" not in m] or [base.model]
    default_ix = next((i for i, m in enumerate(chat_models) if m == base.model or m.split(":")[0] == base.model.split(":")[0]), 0)
    model = st.selectbox("Chat model", chat_models, index=default_ix, disabled=running)
    embed_model = st.text_input("Embedding model", base.embed_model, disabled=running)
    if ol["ok"] and not any(m.split(":")[0] == embed_model.split(":")[0] for m in ol["models"]):
        st.caption(f"`ollama pull {embed_model}` for semantic retrieval (keyword search is used until then).")
    ctx = st.select_slider("Context window (num_ctx)", [2048, 4096, 6144, 8192, 12288, 16384], value=8192, disabled=running)
    timeout = st.number_input("Timeout per model call (s)", 30, 1800, int(base.timeout), 30, disabled=running)
    window = st.slider("Lines of code per model call", 40, 200, base.window_lines, 10, disabled=running)
    max_files = st.slider("Max files to review", 1, 200, base.max_files, disabled=running)
    try:
        import bandit  # noqa: F401
        has_bandit = True
    except ImportError:
        has_bandit = False
    bandit_on = st.checkbox("Use Bandit as extra static source", value=has_bandit, disabled=running or not has_bandit)
    params = {"model": model, "embed_model": embed_model, "ctx": ctx, "timeout": timeout, "window": window,
              "max_files": max_files, "bandit": bandit_on and has_bandit}

# ----------------------------------------------------------------------------
# Pages
# ----------------------------------------------------------------------------
if page == "Review a project":
    st.header("Review a project")
    c1, c2 = st.columns([6, 1])
    c1.text_input("Project folder (or a single file)", key="path", placeholder=r"C:\Users\you\projects\my-app", disabled=running)
    c2.write("")
    c2.write("")
    c2.button("📁 Browse…", on_click=browse_folder, disabled=running)
    if st.session_state.get("browse_error"):
        st.warning(st.session_state.pop("browse_error"))

    path = (st.session_state.get("path") or "").strip().strip('"')
    valid = False
    if path:
        try:
            ws = Workspace(path)
            n = len(ws.files())
            langs = sorted({ws.lang(p) for p in ws.files()})
            valid = n > 0
            if valid:
                st.caption(f"{n} reviewable file(s): {', '.join(langs)}")
            else:
                st.warning("No reviewable source files found there.")
        except ToolError as e:
            st.error(str(e))

    mode_name = st.selectbox("Mode", MODE_ORDER, key="mode", disabled=running)
    st.caption(MODE_HELP[mode_name])
    mode = MODES[mode_name]
    if mode.verify == "llm":
        st.caption("⏱️ The LLM re-check adds one model call per finding. Use `full-det` if your GPU is slow.")
    authorised = st.checkbox("I own this code, or I am explicitly authorised to test it.", key="authorised", disabled=running)

    b1, b2, _ = st.columns([1, 1, 4])
    if b1.button("▶ Run review", key="run", type="primary", disabled=running or not (valid and authorised)):
        start("analyze", f"{Path(path).name} [{mode_name}]", run_analyze, {**params, "path": path, "mode": mode_name})
        st.rerun()
    if b2.button("■ Stop", disabled=not running):
        job.cancel.set()

    if job and job.kind == "analyze":
        st.divider()
        st.subheader(f"{'Running' if running else 'Last run'}: {job.label}")
        if running:
            last = job.logs[-1][1] if job.logs else "starting..."
            st.info(f"Elapsed {time.time() - job.started:.0f}s  |  {last}")
            st.code("\n".join(job.log_text().splitlines()[-25:]) or "...", language="text")
            time.sleep(1)
            st.rerun()
        elif job.error:
            st.error(job.error)
            st.code(job.log_text(), language="text")
        elif job.result is not None:
            render_view(view_from_result(job.result), job.log_text(), job.llm_calls, job.out_dir, key="live")

elif page == "Evaluation":
    st.header("Evaluation on the labelled example apps")
    st.caption("Scores each mode against `examples/` (vulnerable app, clean twin, prompt-injection test). "
               "Model-based modes can take many minutes.")
    picked = st.multiselect("Modes to compare", MODE_ORDER, default=["static", "llm+static+rag", "full-det"], disabled=running)
    if st.button("▶ Run evaluation", type="primary", disabled=running or not picked):
        start("eval", "evaluation", run_eval_job, params, picked)
        st.rerun()
    if running and job.kind == "eval":
        if st.button("■ Stop evaluation"):
            job.cancel.set()
    if job and job.kind == "eval":
        if running:
            st.info(f"Elapsed {time.time() - job.started:.0f}s")
            st.code("\n".join(job.log_text().splitlines()[-25:]) or "...", language="text")
            time.sleep(1)
            st.rerun()
        elif job.error:
            st.error(job.error)
        elif job.result:
            rep = job.result
            st.markdown(evaluate.to_markdown(rep))
            with st.expander("Log"):
                st.code(job.log_text(), language="text")
    else:
        latest = ROOT / "eval" / "results" / "latest.md"
        if latest.exists():
            st.subheader("Latest saved evaluation")
            st.markdown(latest.read_text(encoding="utf-8"))

else:
    st.header("History")
    runs = sorted([d for d in (ROOT / "reports").glob("*") if (d / "findings.json").exists()], reverse=True) if (ROOT / "reports").exists() else []
    if not runs:
        st.info("No saved runs yet. Run a review first.")
    else:
        choice = st.selectbox("Saved run", runs, format_func=lambda d: d.name)
        view = json.loads((choice / "findings.json").read_text(encoding="utf-8"))
        log = (choice / "run.log").read_text(encoding="utf-8") if (choice / "run.log").exists() else ""
        st.caption(f"Target `{view['target']}` | mode `{view['mode']}` | model `{view['model']}`")
        render_view(view, log, None, choice, key="hist")
