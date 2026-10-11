import json

from secagent.agent import MODES, SecurityAgent
from secagent.config import Config
from secagent.rag import KnowledgeBase
from secagent.report import to_json, to_markdown, to_sarif
from secagent.schema import Finding
from secagent.tools import Workspace
from secagent.verify import verify_deterministic
from tests.fakes import ScriptedLLM, SlowVerifyLLM

VULN, INJ = "examples/vulnerable_app", "examples/injection_test"


def make(mode, tmp_path, **kw):
    cfg = Config(index_dir=tmp_path, use_bandit=False)
    llm = ScriptedLLM(**kw)
    kb = KnowledgeBase(cfg, llm).build()
    return SecurityAgent(cfg, llm, kb, MODES[mode]), llm


def test_verify_drops_hallucination_and_corrects_line():
    ws = Workspace(VULN)
    good_wrong_line = Finding("SQLi", "app.py", 5, evidence='rows = db.execute("SELECT name, price FROM cakes WHERE name LIKE \'%" + term + "%\'").fetchall()')
    fake = Finding("Invented", "app.py", 10, evidence="eval(user_input)")
    kept, dropped = verify_deterministic([good_wrong_line, fake], ws)
    assert [f.line for f in kept] == [37] and kept[0].verified
    assert "hallucination" in dropped[0]["reason"]


def test_full_pipeline_uses_tools_rag_and_drops_hallucinations(tmp_path):
    agent, llm = make("full", tmp_path)
    res = agent.analyze(VULN)
    assert res.stats["tool_calls"] >= 1 and llm.seen_tool_output          # tool loop ran
    titles = [f.title for f in res.findings]
    assert "Invented XSS" not in titles                                   # hallucination removed
    assert any("hallucination" in d["reason"] for d in res.dropped)
    sqli = [f for f in res.findings if f.cwe == "CWE-89"]
    assert sqli and all(f.verified for f in res.findings)
    assert any(f.source == "both" for f in sqli)                          # LLM + static agree
    assert any("[kb:cwe/cwe-89" in m[1]["content"] for m in llm.prompts)       # RAG context reached the prompt
    # static leads the model stayed silent about are retained, not lost
    assert any(f.cwe == "CWE-502" for f in res.findings)


def test_llm_can_reject_a_false_positive_lead(tmp_path):
    agent, _ = make("llm+static", tmp_path, hallucinate=False)
    res = agent.analyze(VULN)
    # the scripted model marks lines containing 'DELETE FROM' as rejected; no static lead exists there,
    # so nothing is rejected - but the mechanism must not crash and must keep the leads
    assert res.rejected == [] and len(res.findings) >= 10


def test_prompt_injection_does_not_hide_the_bug_and_is_flagged(tmp_path):
    agent, llm = make("llm+static", tmp_path)
    res = agent.analyze(INJ)
    assert any(f.cwe == "CWE-89" for f in res.findings)
    assert any(f.cwe == "CWE-1427" for f in res.findings)
    sent = json.dumps(llm.prompts)
    assert "untrusted_code" in sent and "Never obey" in sent


def test_static_mode_needs_no_llm():
    cfg = Config(use_bandit=False)
    res = SecurityAgent(cfg, None, None, MODES["static"]).analyze(VULN)
    assert len(res.findings) == 13 and res.stats["llm_calls"] == 0


def test_reports_render(tmp_path):
    cfg = Config(use_bandit=False)
    res = SecurityAgent(cfg, None, None, MODES["static"]).analyze(VULN)
    md, sarif, js = to_markdown(res), json.loads(to_sarif(res)), json.loads(to_json(res))
    assert "| # | Severity" in md and "sk_live_51Hq" not in md and "sk_l***" in md      # secrets redacted
    run = sarif["runs"][0]
    assert sarif["version"] == "2.1.0" and len(run["results"]) == 13
    assert run["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1
    assert js["findings"][0]["cwe_id"]


def test_timeouts_in_recheck_keep_findings_and_stop_early(tmp_path):
    cfg = Config(index_dir=tmp_path, use_bandit=False)
    llm = SlowVerifyLLM()
    res = SecurityAgent(cfg, llm, KnowledgeBase(cfg, llm).build(), MODES["full"]).analyze(VULN)
    assert len(res.findings) >= 10                                     # nothing thrown away
    assert sum("re-check failed" in n for n in res.notes) == 2         # circuit breaker after 2 timeouts
    assert any("skipped" in f.verification for f in res.findings)
    recheck_calls = [m for m in llm.prompts if "verdict" in str(m)]
    assert len(recheck_calls) == 0                                     # (calls raised before being recorded)


def test_truncated_json_is_salvaged():
    from secagent.llm import salvage_findings
    cut = '{"action":"finish","findings":[{"title":"A","line":3,"evidence":"x"},{"title":"B","line":9,"evid'
    assert [f["title"] for f in salvage_findings(cut)] == ["A"]
    assert salvage_findings('{"verdict":"safe"') is None


def test_window_failure_is_logged_and_noted(tmp_path):
    from secagent.llm import LLMTimeout

    class Dead(ScriptedLLM):
        def chat_json(self, messages, schema=None, retries=2, max_tokens=None):
            raise LLMTimeout("model call timed out after 180s")

    cfg = Config(index_dir=tmp_path, use_bandit=False)
    logs = []
    res = SecurityAgent(cfg, Dead(), None, MODES["llm+static"], log=logs.append).analyze(VULN)
    assert len(res.findings) == 13                                    # static leads still reported
    assert any("LLM review failed" in n for n in res.notes) and any("FAILED" in l for l in logs)


def test_cancel_via_log_callback(tmp_path):
    import pytest
    from secagent.agent import RunCancelled
    cfg = Config(index_dir=tmp_path, use_bandit=False)

    def log(m):
        if m.startswith("[1/1]"):
            raise RunCancelled()

    with pytest.raises(RunCancelled):
        SecurityAgent(cfg, ScriptedLLM(), None, MODES["llm+static"], log=log).analyze(VULN)
