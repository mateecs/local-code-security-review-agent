from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path

from . import __version__
from .agent import MODES, SecurityAgent
from .config import Config, ROOT
from .llm import LLMError, LLMUnavailable, OllamaLLM
from .rag import KnowledgeBase
from .report import to_json, to_markdown, to_sarif


def _log(verbose: bool):
    return (lambda m: print(m, file=sys.stderr)) if verbose else (lambda m: None)


def _setup(args, need_llm: bool = True):
    cfg = Config()
    if getattr(args, "model", None):
        cfg.model = args.model
    if getattr(args, "ctx", None):
        cfg.num_ctx = args.ctx
    if getattr(args, "timeout", None):
        cfg.timeout = args.timeout
    if getattr(args, "no_bandit", False):
        cfg.use_bandit = False
    llm = OllamaLLM(cfg) if need_llm else None
    return cfg, llm


def cmd_doctor(args) -> int:
    cfg, llm = _setup(args)
    ok = True
    print(f"secagent {__version__} | host {cfg.host} | chat model {cfg.model} | embed model {cfg.embed_model} | num_ctx {cfg.num_ctx}")
    try:
        models = llm.installed_models()
    except LLMError as e:
        print(f"[FAIL] {e}")
        return 1
    print(f"[ ok ] Ollama reachable, {len(models)} model(s) installed")
    for need, label in ((cfg.model, "chat model"), (cfg.embed_model, "embedding model")):
        have = any(m == need or m.split(":")[0] == need.split(":")[0] and ":" not in need for m in models)
        print(f"[{' ok ' if have else 'WARN'}] {label} '{need}' " + ("installed" if have else f"missing -> ollama pull {need}"
              + ("   (retrieval falls back to keyword search)" if label == "embedding model" else "")))
        ok &= have or label == "embedding model"
    if ok:
        try:
            b = llm.benchmark()
            print(f"[ ok ] speed: {b['tok_per_s']} tokens/s ({b['tokens']} tokens in {b['wall_s']}s). Note this for your README.")
            for m in llm.loaded_models():
                hint = "" if m["gpu_pct"] in (None, 100) else "   <- partly on CPU: lower --ctx (e.g. 4096) or close GPU-heavy apps"
                print(f"[info] loaded: {m['name']} ({m['gpu_pct']}% on GPU){hint}")
        except Exception as e:
            print(f"[WARN] benchmark failed: {e}")
    try:
        import bandit  # noqa: F401
        print("[ ok ] bandit installed (extra static source)")
    except ImportError:
        print("[info] bandit not installed (optional): pip install bandit")
    n = len(list(cfg.kb_dir.rglob("*.md"))) if cfg.kb_dir.exists() else 0
    print(f"[{' ok ' if n else 'WARN'}] knowledge base: {n} markdown file(s) in {cfg.kb_dir}")
    return 0 if ok else 1


def cmd_index(args) -> int:
    cfg, llm = _setup(args)
    kb = KnowledgeBase(cfg, llm, log=print).build()
    print(f"Indexed {len(kb.chunks)} chunks from {cfg.kb_dir} ({'hybrid BM25+embeddings' if kb.vectors is not None else 'BM25 only'})")
    return 0


def cmd_analyze(args) -> int:
    mode = MODES[args.mode]
    cfg, llm = _setup(args, need_llm=mode.use_llm)
    kb = KnowledgeBase(cfg, llm, log=print).load_or_build() if mode.use_rag else None
    try:
        res = SecurityAgent(cfg, llm, kb, mode, log=_log(not args.quiet)).analyze(args.path)
    except LLMUnavailable as e:
        print(f"\nError: {e}\nTip: run `python -m secagent doctor`, or use `--mode static` (no model needed).", file=sys.stderr)
        return 2
    out = Path(args.out) if args.out else ROOT / "reports" / f"{Path(args.path).resolve().name}-{mode.name}-{datetime.now():%Y%m%d-%H%M%S}"
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.md").write_text(to_markdown(res), encoding="utf-8")
    (out / "findings.json").write_text(to_json(res), encoding="utf-8")
    (out / "report.sarif").write_text(to_sarif(res), encoding="utf-8")
    print(f"\n{len(res.findings)} finding(s) | {len(res.dropped)} removed by verification | {res.stats['seconds']}s")
    for f in res.findings:
        print(f"  [{f.severity:<8}] {f.file}:{f.line:<4} {f.cwe or '-':<9} {f.title[:70]}  ({f.source}, conf {f.confidence:.2f})")
    print(f"\nReports written to {out}")
    return 0


def cmd_eval(args) -> int:
    from . import evaluate
    names = [m.strip() for m in args.modes.split(",")]
    bad = [m for m in names if m not in MODES]
    if bad:
        print(f"Unknown mode(s): {bad}. Available: {', '.join(MODES)}")
        return 2
    need_llm = any(MODES[m].use_llm for m in names)
    cfg, llm = _setup(args, need_llm=need_llm)
    kb = KnowledgeBase(cfg, llm, log=print).load_or_build() if any(MODES[m].use_rag for m in names) else None
    try:
        report = evaluate.run_eval(cfg, llm, kb, names)
    except LLMUnavailable as e:
        print(f"\nError: {e}", file=sys.stderr)
        return 2
    md = evaluate.save(report)
    print("\n" + evaluate.to_markdown(report) + f"\nSaved to {md}")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="secagent", description="Local AI security-review agent (offline, Ollama)")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp):
        sp.add_argument("--model", help="Ollama chat model (default: qwen2.5-coder:7b)")
        sp.add_argument("--ctx", type=int, help="context window (num_ctx), default 8192")
        sp.add_argument("--timeout", type=float, help="seconds allowed per model call (default 180)")
        sp.add_argument("--no-bandit", action="store_true", help="do not use Bandit even if installed")

    sub.add_parser("doctor", help="check Ollama, models, speed, knowledge base").set_defaults(fn=cmd_doctor)
    common(sub.choices["doctor"])
    sp = sub.add_parser("index", help="(re)build the knowledge-base index"); common(sp); sp.set_defaults(fn=cmd_index)

    sp = sub.add_parser("analyze", help="review a codebase")
    sp.add_argument("path", help="file or directory you own / are authorised to test")
    sp.add_argument("--mode", default="full", choices=list(MODES), help="ablation mode (default: full)")
    sp.add_argument("--out", help="output directory for report.md / findings.json / report.sarif")
    sp.add_argument("--quiet", action="store_true")
    common(sp); sp.set_defaults(fn=cmd_analyze)

    sp = sub.add_parser("eval", help="score modes against labelled example apps")
    sp.add_argument("--modes", default="static,llm-only,llm+static+rag,full")
    common(sp); sp.set_defaults(fn=cmd_eval)

    args = p.parse_args(argv)
    return args.fn(args)
