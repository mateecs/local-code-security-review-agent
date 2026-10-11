from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


@dataclass
class Config:
    # --- model / runtime -------------------------------------------------
    model: str = os.getenv("SECAGENT_MODEL", "qwen2.5-coder:7b")
    embed_model: str = os.getenv("SECAGENT_EMBED_MODEL", "nomic-embed-text")
    host: str = os.getenv("OLLAMA_HOST", "http://localhost:11434")
    num_ctx: int = int(os.getenv("SECAGENT_NUM_CTX", "8192"))  # Ollama's default is far smaller
    temperature: float = 0.1
    seed: int = 42
    timeout: float = float(os.getenv("SECAGENT_TIMEOUT", "180"))   # seconds per model call
    max_tokens_review: int = 3000   # cap output so a stuck generation cannot run for minutes
    max_tokens_verify: int = 300
    # --- agent behaviour -------------------------------------------------
    max_steps: int = 4            # tool-use steps per code window (last step must 'finish')
    window_lines: int = 100       # lines of code per LLM call (VRAM / context budget)
    window_overlap: int = 10
    max_files: int = 40
    max_file_bytes: int = 400_000
    use_bandit: bool = True       # use Bandit as an extra static source if installed
    # --- knowledge base --------------------------------------------------
    kb_dir: Path = ROOT / "data" / "knowledge"
    index_dir: Path = ROOT / "data" / "index"
    kb_top_k: int = 3
    # --- verification ----------------------------------------------------
    llm_verify_drop_conf: float = 0.8   # drop a finding only if the re-check says "safe" this confidently
