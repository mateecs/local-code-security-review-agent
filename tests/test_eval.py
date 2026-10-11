from pathlib import Path

from secagent.config import ROOT
from secagent.evaluate import load_truth, score
from secagent.agent import MODES, SecurityAgent
from secagent.config import Config


def test_ground_truth_lines_resolve():
    t = load_truth(ROOT / "eval" / "ground_truth" / "vulnerable_app.json")
    assert len(t["vulns"]) == 14 and all(v["line"] > 0 for v in t["vulns"])


def test_ground_truth_is_not_inside_scanned_targets():
    # the agent must never be able to read the answers
    for gt in (ROOT / "eval" / "ground_truth").glob("*.json"):
        assert not list((ROOT / "examples").rglob(gt.name))


def test_static_baseline_scores():
    cfg = Config(use_bandit=False)
    t = load_truth(ROOT / "eval" / "ground_truth" / "vulnerable_app.json")
    s = score(t, SecurityAgent(cfg, None, None, MODES["static"]).analyze(t["target_path"]).findings)
    assert s["tp"] == 13 and s["missed"] == ["V13"] and s["fp"] == 0       # SSRF is the one thing rules cannot see
    c = load_truth(ROOT / "eval" / "ground_truth" / "clean_app.json")
    assert score(c, SecurityAgent(cfg, None, None, MODES["static"]).analyze(c["target_path"]).findings)["fp"] == 0
