"""A scripted stand-in for the model so the whole pipeline is testable without Ollama."""
import json
import re

from secagent.llm import LLMError, LLMTimeout


class ScriptedLLM:
    """Behaves like a mediocre-but-plausible reviewer:
       - first asks to read_file (exercises the tool loop) when tools are allowed,
       - reports every `.execute(` line that concatenates/f-strings SQL,
       - always adds one hallucinated finding (evidence not in the file),
       - rejects any lead on a line containing 'DELETE FROM' (a false-positive lead),
       - answers the verification question 'safe' for md5 findings."""

    def __init__(self, hallucinate=True):
        self.stats = {"calls": 0, "prompt_tokens": 0, "output_tokens": 0, "seconds": 0.0}
        self.hallucinate = hallucinate
        self.seen_tool_output = False
        self.prompts = []

    def embed(self, texts):
        raise LLMError("no embedding model in tests")

    def chat_json(self, messages, schema=None, retries=2, max_tokens=None):
        self.stats["calls"] += 1
        user = messages[-1]["content"]
        first = messages[1]["content"]
        self.prompts.append(messages)
        props = schema["properties"]
        if "verdict" in props:
            return {"verdict": "safe" if "md5" in user.lower() else "likely", "reasoning": "scripted", "confidence": 0.9}
        if "<tool_output" in user:
            self.seen_tool_output = True
        actions = props["action"]["enum"]
        if "read_file" in actions and not self.seen_tool_output and "<tool_output" not in user:
            return {"action": "read_file", "path": re.search(r'file="([^"]+)"', first).group(1), "start": 1, "end": 5}
        file = re.search(r'<untrusted_code file="([^"]+)"', first).group(1)
        findings = []
        for m in re.finditer(r"^\s*(\d+)\| (.*)$", first, re.M):
            ln, code = int(m.group(1)), m.group(2)
            if ".execute(" in code and ("+" in code or 'f"' in code or "query" in code):
                findings.append({"title": "SQL injection", "cwe": "CWE-89", "severity": "high", "line": ln,
                                 "evidence": code.strip(), "explanation": "user input reaches SQL", "remediation": "parameterise", "confidence": 0.8})
        if self.hallucinate and findings:
            findings.append({"title": "Invented XSS", "cwe": "CWE-79", "severity": "high", "line": 3,
                             "evidence": "return render(user_input)  # not in file", "explanation": "x", "remediation": "y", "confidence": 0.9})
        rejected = [{"line": int(m.group(1)), "reason": "parameterised"} for m in re.finditer(r"^\s*(\d+)\| .*DELETE FROM", first, re.M)]
        return {"action": "finish", "findings": findings, "rejected_leads": rejected}


class SlowVerifyLLM(ScriptedLLM):
    """Review works, but every re-check call times out (what happened on a slow 8 GB GPU)."""

    def chat_json(self, messages, schema=None, retries=2, max_tokens=None):
        if "verdict" in schema["properties"]:
            self.stats["calls"] += 1
            raise LLMTimeout("model call timed out after 180s")
        return super().chat_json(messages, schema, retries, max_tokens)
