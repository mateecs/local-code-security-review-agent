"""Local knowledge base: markdown -> chunks -> hybrid (BM25 + embeddings) retrieval.

~30 chunks do not need a vector database: brute-force cosine is exact and has no
install friction. If the embedding model is missing we silently fall back to BM25
so the agent still works.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from collections import Counter
from dataclasses import asdict, dataclass

import numpy as np

from .config import Config
from .llm import LLMError


@dataclass
class Chunk:
    id: int
    source: str
    heading: str
    text: str


def _split_sections(text: str):
    title, sections, head, cur, fence = "", [], "", [], False
    for line in text.splitlines():
        if line.strip().startswith("```"):
            fence = not fence
        if not fence and line.startswith("# ") and not title:
            title = line[2:].strip()
            continue
        if not fence and line.startswith("## "):
            if cur:
                sections.append((head, "\n".join(cur).strip()))
            head, cur = line[3:].strip(), []
            continue
        cur.append(line)
    if cur:
        sections.append((head, "\n".join(cur).strip()))
    return title, [s for s in sections if s[1]]


def _split_long(text: str, max_chars: int) -> list[str]:
    paras, buf, fence, parts = [], [], False, []
    for line in text.splitlines():
        if line.strip().startswith("```"):
            fence = not fence
        if not line.strip() and not fence:
            if buf:
                paras.append("\n".join(buf))
                buf = []
        else:
            buf.append(line)
    if buf:
        paras.append("\n".join(buf))
    cur = ""
    for p in paras:
        if cur and len(cur) + len(p) > max_chars:
            parts.append(cur)
            cur = ""
        cur = f"{cur}\n\n{p}".strip()
    if cur:
        parts.append(cur)
    return parts or [text]


def chunk_markdown(text: str, source: str, start_id: int = 0, max_chars: int = 1400) -> list[Chunk]:
    title, sections = _split_sections(text)
    out: list[Chunk] = []
    for head, body in sections:
        label = f"{title} - {head}" if head and title else (head or title or source)
        for part in (_split_long(body, max_chars) if len(body) > max_chars else [body]):
            out.append(Chunk(start_id + len(out), source, head, f"{label}\n{part}"))
    return out


_tok = lambda s: re.findall(r"[a-z0-9]+", s.lower())


class BM25:
    def __init__(self, docs: list[str], k1: float = 1.5, b: float = 0.75):
        self.k1, self.b = k1, b
        self.tf = [Counter(_tok(d)) for d in docs]
        self.len = [sum(c.values()) for c in self.tf]
        self.avg = (sum(self.len) / len(docs)) if docs else 0
        df = Counter(w for c in self.tf for w in c)
        n = len(docs)
        self.idf = {w: math.log(1 + (n - c + 0.5) / (c + 0.5)) for w, c in df.items()}

    def scores(self, query: str) -> list[float]:
        q = _tok(query)
        out = []
        for tf, ln in zip(self.tf, self.len):
            s = 0.0
            for w in q:
                if w in tf:
                    f = tf[w]
                    s += self.idf[w] * f * (self.k1 + 1) / (f + self.k1 * (1 - self.b + self.b * ln / (self.avg or 1)))
            out.append(s)
        return out


class KnowledgeBase:
    def __init__(self, cfg: Config, llm=None, log=lambda m: None):
        self.cfg, self.llm, self.log = cfg, llm, log
        self.chunks: list[Chunk] = []
        self.vectors: np.ndarray | None = None
        self.bm25: BM25 | None = None

    # -- building ---------------------------------------------------------
    def _files(self):
        d = self.cfg.kb_dir
        return sorted([*d.rglob("*.md"), *d.rglob("*.txt")]) if d.exists() else []

    def _fingerprint(self, files) -> str:
        h = hashlib.sha256()
        for f in files:
            h.update(f.relative_to(self.cfg.kb_dir).as_posix().encode())
            h.update(f.read_bytes())
        return h.hexdigest()[:16]

    def _doc_prefix(self) -> str:
        return "search_document: " if "nomic" in self.cfg.embed_model else ""

    def _query_prefix(self) -> str:
        return "search_query: " if "nomic" in self.cfg.embed_model else ""

    def build(self) -> "KnowledgeBase":
        files = self._files()
        if not files:
            raise FileNotFoundError(f"No knowledge files found in {self.cfg.kb_dir}")
        self.chunks = []
        for f in files:
            src = f.relative_to(self.cfg.kb_dir).as_posix()
            self.chunks += chunk_markdown(f.read_text(encoding="utf-8", errors="replace"), src, len(self.chunks))
        self.bm25 = BM25([c.text for c in self.chunks])
        self.vectors = None
        if self.llm is not None:
            try:
                vecs = []
                texts = [self._doc_prefix() + c.text for c in self.chunks]
                for i in range(0, len(texts), 16):
                    vecs += self.llm.embed(texts[i:i + 16])
                m = np.asarray(vecs, dtype=np.float32)
                self.vectors = m / np.linalg.norm(m, axis=1, keepdims=True).clip(1e-9)
            except LLMError as e:
                self.log(f"[kb] embeddings unavailable ({e}); using keyword (BM25) retrieval only")
        self.cfg.index_dir.mkdir(parents=True, exist_ok=True)
        (self.cfg.index_dir / "kb_chunks.json").write_text(json.dumps([asdict(c) for c in self.chunks]), encoding="utf-8")
        if self.vectors is not None:
            np.save(self.cfg.index_dir / "kb_vectors.npy", self.vectors)
        (self.cfg.index_dir / "kb_meta.json").write_text(json.dumps({
            "fingerprint": self._fingerprint(files), "embed_model": self.cfg.embed_model,
            "chunks": len(self.chunks), "has_vectors": self.vectors is not None}), encoding="utf-8")
        return self

    def load_or_build(self) -> "KnowledgeBase":
        meta_p = self.cfg.index_dir / "kb_meta.json"
        try:
            meta = json.loads(meta_p.read_text(encoding="utf-8"))
            fresh = meta["fingerprint"] == self._fingerprint(self._files()) and meta["embed_model"] == self.cfg.embed_model
            if fresh and (meta["has_vectors"] or self.llm is None):
                self.chunks = [Chunk(**c) for c in json.loads((self.cfg.index_dir / "kb_chunks.json").read_text(encoding="utf-8"))]
                self.bm25 = BM25([c.text for c in self.chunks])
                vp = self.cfg.index_dir / "kb_vectors.npy"
                self.vectors = np.load(vp) if meta["has_vectors"] and vp.exists() else None
                return self
        except (OSError, KeyError, ValueError):
            pass
        return self.build()

    # -- retrieval --------------------------------------------------------
    def search(self, query: str, k: int | None = None) -> list[Chunk]:
        k = k or self.cfg.kb_top_k
        if not self.chunks:
            return []
        rankings: list[list[int]] = []
        bm = self.bm25.scores(query)
        rankings.append([i for i in np.argsort(bm)[::-1][:10] if bm[i] > 0])
        if self.vectors is not None and self.llm is not None:
            try:
                q = np.asarray(self.llm.embed([self._query_prefix() + query])[0], dtype=np.float32)
                q /= max(np.linalg.norm(q), 1e-9)
                sims = self.vectors @ q
                rankings.append([int(i) for i in np.argsort(sims)[::-1][:10]])
            except LLMError:
                pass
        fused: dict[int, float] = {}
        for r in rankings:                      # reciprocal-rank fusion
            for rank, idx in enumerate(r):
                fused[int(idx)] = fused.get(int(idx), 0.0) + 1.0 / (60 + rank)
        return [self.chunks[i] for i, _ in sorted(fused.items(), key=lambda kv: -kv[1])[:k]]
