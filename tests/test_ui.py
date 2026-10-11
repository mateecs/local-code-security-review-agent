import time
from pathlib import Path

from streamlit.testing.v1 import AppTest

UI = Path(__file__).resolve().parent.parent / "ui.py"


def _settle(at, seconds=8):
    t0 = time.time()
    while time.time() - t0 < seconds:
        at.run(timeout=10)
        if not at.exception and not any("Running" in s.value for s in at.subheader):
            return
        time.sleep(0.5)


def test_ui_loads_without_ollama():
    at = AppTest.from_file(str(UI), default_timeout=15).run()
    assert not at.exception
    assert any("Ollama not reachable" in e.value for e in at.sidebar.error)


def test_static_review_end_to_end_through_the_ui():
    at = AppTest.from_file(str(UI), default_timeout=15).run()
    at.text_input(key="path").set_value("examples/vulnerable_app").run()
    run = at.button(key="run")
    assert run.disabled                                   # blocked until authorisation is ticked
    at.checkbox(key="authorised").check().run()
    at.selectbox(key="mode").select("static").run()
    at.button(key="run").click().run()
    _settle(at)
    assert not at.exception, at.exception
    assert any("Last run" in s.value for s in at.subheader)
    assert any(m.label == "Findings" and int(m.value) >= 13 for m in at.metric)   # 13 rules + Bandit extras
