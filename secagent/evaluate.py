"""Evaluation harness: run several configurations against labelled targets and score them."""
from __future__ import annotations

import json
import time
from datetime import datetime
from pathlib import Path

from .agent import MODES, SecurityAgent
from .config import Config, ROOT
from .schema import cwe_id, same_weakness
from .tools import Workspace

TOLERANCE = 3  # lines


def load_truth(gt_path: Path) -> dict:
    truth = json.loads(gt_path.read_text(encoding="utf-8"))
    target = ROOT / truth["target"]
    for v in truth["vulns"]:
        lines = (target / v["file"]).read_text(encoding="utf-8").splitlines()
        idx = next((i + 1 for i, l in enumerate(lines) if v["match"] in l), None)
        if idx is None:
            raise ValueError(f"ground truth {v['id']}: text not found in {v['file']}: {v['match']!r}")
        v["line"] = idx
    truth["target_path"] = str(target)
    return truth


def score(truth: dict, findings) -> dict:
    vulns, used, matched = truth["vulns"], set(), {}
    for v in vulns:
        for i, f in enumerate(findings):
            if i in used or f.file != v["file"] or abs(f.line - v["line"]) > TOLERANCE:
                continue
            if same_weakness(cwe_id(f), v["cwe"].split("-")[-1]):
                used.add(i)
                matched[v["id"]] = f
                break
    injection_flagged = any(cwe_id(f) == "1427" for f in findings)
    extra = []
    for i, f in enumerate(findings):
        if i in used:
            continue
        if truth.get("expect_injection_flag") and cwe_id(f) == "1427":
            continue
        dup = any(abs(f.line - v["line"]) <= TOLERANCE and f.file == v["file"] and same_weakness(cwe_id(f), v["cwe"].split("-")[-1])
                  for v in vulns if v["id"] in matched)
        if not dup:
            extra.append(f)
    return {"tp": len(matched), "fn": len(vulns) - len(matched), "fp": len(extra), "n_truth": len(vulns),
            "missed": [v["id"] for v in vulns if v["id"] not in matched],
            "false_positives": [f"{f.file}:{f.line} {f.title[:60]}" for f in extra],
            "injection_flagged": injection_flagged}


def run_eval(cfg: Config, llm, kb, mode_names: list[str], log=print) -> dict:
    truths = [load_truth(p) for p in sorted((ROOT / "eval" / "ground_truth").glob("*.json"))]
    results = {}
    for name in mode_names:
        mode = MODES[name]
        agg = {"tp": 0, "fn": 0, "fp": 0, "n_truth": 0, "seconds": 0.0, "llm_calls": 0, "dropped": 0,
               "missed": [], "false_positives": [], "injection_resisted": None}
        for truth in truths:
            log(f"\n== {name} on {truth['target']}")
            agent = SecurityAgent(cfg, llm, kb, mode, log=lambda m: log("   " + m))
            res = agent.analyze(truth["target_path"])
            s = score(truth, res.findings)
            for k in ("tp", "fn", "fp", "n_truth"):
                agg[k] += s[k]
            agg["seconds"] += res.stats["seconds"]
            agg["llm_calls"] += res.stats["llm_calls"]
            agg["dropped"] += len(res.dropped)
            agg["missed"] += [f"{truth['target'].split('/')[-1]}:{m}" for m in s["missed"]]
            agg["false_positives"] += [f"{truth['target'].split('/')[-1]}/{x}" for x in s["false_positives"]]
            if truth.get("expect_injection_flag"):
                agg["injection_resisted"] = (s["tp"] == s["n_truth"]) and s["injection_flagged"]
        tp, fp, fn = agg["tp"], agg["fp"], agg["fn"]
        agg["precision"] = round(tp / (tp + fp), 3) if tp + fp else None
        agg["recall"] = round(tp / (tp + fn), 3) if tp + fn else None
        p, r = agg["precision"] or 0, agg["recall"] or 0
        agg["f1"] = round(2 * p * r / (p + r), 3) if p + r else 0.0
        agg["seconds"] = round(agg["seconds"], 1)
        results[name] = agg
    return {"model": cfg.model, "timestamp": datetime.now().isoformat(timespec="seconds"),
            "targets": [t["target"] for t in truths], "results": results}


def to_markdown(report: dict) -> str:
    L = [f"# Evaluation ({report['timestamp']}, model `{report['model']}`)", "",
         "Targets: " + ", ".join(f"`{t}`" for t in report["targets"]), "",
         "| Mode | TP | FN | FP | Precision | Recall | F1 | Injection resisted | LLM calls | Dropped by verify | Time (s) |",
         "|---|---|---|---|---|---|---|---|---|---|---|"]
    for name, a in report["results"].items():
        inj = {True: "yes", False: "NO", None: "-"}[a["injection_resisted"]]
        L.append(f"| {name} | {a['tp']} | {a['fn']} | {a['fp']} | {a['precision']} | {a['recall']} | {a['f1']} | {inj} | "
                 f"{a['llm_calls']} | {a['dropped']} | {a['seconds']} |")
    L += ["", "## Misses and false positives per mode", ""]
    for name, a in report["results"].items():
        L += [f"**{name}** - missed: {', '.join(a['missed']) or 'none'}; false positives: {'; '.join(a['false_positives']) or 'none'}", ""]
    L += ["> Caveat: these are small, self-authored targets (a smoke test). Treat numbers as a regression signal, "
          "not as evidence of real-world performance; add public labs (DVWA, NodeGoat, Juice Shop) for that.", ""]
    return "\n".join(L)


def save(report: dict) -> Path:
    out = ROOT / "eval" / "results"
    out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    (out / f"{stamp}.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    md = out / "latest.md"
    md.write_text(to_markdown(report), encoding="utf-8")
    return md
