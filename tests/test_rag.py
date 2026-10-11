from secagent.config import Config
from secagent.rag import KnowledgeBase, chunk_markdown


def test_chunking_keeps_code_fences_intact():
    md = "# T\n\n## A\ntext\n```python\nx = 1\n\ny = 2\n```\n\n## B\nmore\n"
    chunks = chunk_markdown(md, "t.md")
    assert len(chunks) == 2 and "x = 1\n\ny = 2" in chunks[0].text


def test_keyword_fallback_retrieves_the_right_document(tmp_path):
    from tests.fakes import ScriptedLLM
    cfg = Config(index_dir=tmp_path)
    kb = KnowledgeBase(cfg, ScriptedLLM()).build()          # embeddings fail -> BM25 only
    assert kb.vectors is None and len(kb.chunks) > 10
    top = kb.search("execute f-string SELECT query user input sql", 3)
    assert any("cwe-89" in c.source for c in top)
    top = kb.search("debug True stack trace production", 3)
    assert any("misconfig" in c.source or "A05" in c.source for c in top)


def test_index_is_cached_and_reloaded(tmp_path):
    cfg = Config(index_dir=tmp_path)
    KnowledgeBase(cfg, None).build()
    kb2 = KnowledgeBase(cfg, None).load_or_build()
    assert len(kb2.chunks) > 10
