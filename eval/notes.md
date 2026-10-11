# Experiment log

Record every experiment here, including the ones that failed. Use `python -m secagent eval ...`;
results land in `eval/results/` (JSON per run + `latest.md`).

| # | Date | Change | Mode / model | P | R | F1 | What I learned |
|---|------|--------|--------------|---|---|----|----------------|
| 1 |      | Baseline: static rules only | static | | | | |
| 2 |      | Bare LLM, no hints | llm-only / qwen2.5-coder:7b | | | | |
| 3 |      | + static leads | llm+static | | | | |
| 4 |      | + RAG (ablation) | llm+static+rag | | | | |
| 5 |      | + tools + LLM re-check | full | | | | |
| 6 |      | Model swap | full / qwen3:8b | | | | |

## Questions to answer with data
- Does RAG help a 7B model, or does it only add prompt noise? (compare rows 3 and 4)
- How many hallucinated findings does deterministic verification remove? (`full-noverify` vs `full`, "Dropped" column)
- Does the model obey a prompt-injection comment? (`Injection resisted` column)
- Tokens/second and VRAM headroom on the RTX 4060 (`python -m secagent doctor`).
