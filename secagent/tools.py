"""Deterministic, read-only tools.

Everything the LLM can touch lives here, behind `Workspace`, which confines all
access to the target directory (no writes, no network, no shell execution).
"""
from __future__ import annotations

import ast
import json
import math
import os
import re
import shutil
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from .schema import Candidate, cwe_id

LANG_BY_EXT = {
    ".py": "python", ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".java": "java", ".php": "php",
    ".rb": "ruby", ".go": "go", ".sh": "shell", ".yml": "yaml", ".yaml": "yaml",
    ".ini": "config", ".cfg": "config", ".toml": "config", ".conf": "config",
    ".env": "env", ".json": "json", ".txt": "text",
}
TEXT_ONLY_IF_NAMED = {"requirements.txt"}          # .txt files are skipped unless listed here
SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build",
             ".idea", ".mypy_cache", ".pytest_cache", "site-packages", ".tox"}
SKIP_FILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Pipfile.lock"}


class ToolError(Exception):
    pass


# --------------------------------------------------------------------------
# Workspace (sandbox)
# --------------------------------------------------------------------------
class Workspace:
    def __init__(self, path: str | Path, max_bytes: int = 400_000):
        p = Path(path).resolve()
        if not p.exists():
            raise ToolError(f"path not found: {path}")
        self.single = p if p.is_file() else None
        self.root = p.parent if p.is_file() else p
        self.max_bytes = max_bytes
        self._files: list[Path] | None = None
        self._lines: dict[str, list[str]] = {}

    # -- paths -------------------------------------------------------------
    def rel(self, p: Path) -> str:
        return p.relative_to(self.root).as_posix()

    def resolve(self, rel: str) -> Path:
        if not rel or "\x00" in rel:
            raise ToolError("invalid path")
        p = (self.root / rel).resolve()
        try:
            p.relative_to(self.root)
        except ValueError:
            raise ToolError("path escapes the workspace") from None
        if not p.is_file():
            raise ToolError(f"file not found: {rel}")
        return p

    def lang(self, p: Path) -> str | None:
        name = p.name.lower()
        if name == "dockerfile":
            return "docker"
        if name.startswith(".env"):
            return "env"
        if p.suffix.lower() == ".txt":
            return "text" if name in TEXT_ONLY_IF_NAMED else None
        return LANG_BY_EXT.get(p.suffix.lower())

    # -- listing -----------------------------------------------------------
    def files(self) -> list[Path]:
        if self._files is not None:
            return self._files
        if self.single:
            self._files = [self.single]
            return self._files
        out: list[Path] = []
        for dirpath, dirnames, filenames in os.walk(self.root, followlinks=False):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fn in filenames:
                p = Path(dirpath) / fn
                if p.is_symlink() or fn in SKIP_FILES or not self.lang(p):
                    continue
                limit = 50_000 if self.lang(p) == "json" else self.max_bytes
                try:
                    if p.stat().st_size > limit:
                        continue
                    with open(p, "rb") as fh:
                        if b"\0" in fh.read(2048):
                            continue
                except OSError:
                    continue
                out.append(p)
        self._files = sorted(out)
        return self._files

    def rels(self) -> list[str]:
        return [self.rel(p) for p in self.files()]

    def lines(self, rel: str) -> list[str]:
        if rel not in self._lines:
            self._lines[rel] = self.resolve(rel).read_text(encoding="utf-8", errors="replace").splitlines()
        return self._lines[rel]

    def text(self, rel: str) -> str:
        return "\n".join(self.lines(rel))

    # -- LLM-facing tools --------------------------------------------------
    def list_files(self) -> str:
        rows = [f"{self.rel(p)}  ({self.lang(p)}, {len(self.lines(self.rel(p)))} lines)" for p in self.files()]
        return "\n".join(rows) or "(no source files found)"

    def read_file(self, path: str, start: int = 1, end: int | None = None, max_lines: int = 150) -> str:
        lines = self.lines(self.rel(self.resolve(path)))
        n = len(lines)
        start = max(1, int(start or 1))
        end = min(int(end or (start + max_lines - 1)), start + max_lines - 1, n)
        if start > n:
            raise ToolError(f"{path} has only {n} lines")
        body = "\n".join(f"{i:4d}| {lines[i - 1]}" for i in range(start, end + 1))
        return f"# {path} lines {start}-{end} of {n}\n{body}"

    def search_code(self, pattern: str, max_results: int = 25) -> str:
        if not pattern or len(pattern) > 200:
            raise ToolError("pattern must be 1-200 characters")
        try:
            rx = re.compile(pattern, re.I)
        except re.error as e:
            raise ToolError(f"bad regex: {e}") from None
        hits: list[str] = []
        for rel in self.rels():
            for i, line in enumerate(self.lines(rel), 1):
                if rx.search(line[:400]):
                    hits.append(f"{rel}:{i}: {line.strip()[:160]}")
                    if len(hits) >= max_results:
                        return "\n".join(hits) + "\n(results truncated)"
        return "\n".join(hits) or "(no matches)"


def numbered(lines: list[str], start: int) -> str:
    return "\n".join(f"{start + i:4d}| {ln}" for i, ln in enumerate(lines))


# --------------------------------------------------------------------------
# Regex rules
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class Rule:
    id: str
    cwe: str
    severity: str
    langs: tuple
    rx: re.Pattern
    message: str


def _r(id, cwe, sev, langs, pattern, msg):
    return Rule(id, cwe, sev, tuple(langs), re.compile(pattern, re.I if id.startswith(("JS-", "CFG-")) else 0), msg)


RULES = [
    _r("PY-CMD-SHELL", "CWE-78", "high", ["python"], r"subprocess\.\w+\(.*shell\s*=\s*True", "subprocess call with shell=True (command injection risk)"),
    _r("PY-OS-SYSTEM", "CWE-78", "high", ["python"], r"\bos\.(system|popen)\(", "os.system/os.popen executes a shell command"),
    _r("PY-EVAL", "CWE-95", "high", ["python"], r"(?<![\w.])(eval|exec)\(", "eval/exec on dynamic input"),
    _r("PY-PICKLE", "CWE-502", "high", ["python"], r"\b(pickle|cPickle|dill)\.loads?\(", "unsafe deserialization with pickle"),
    _r("PY-YAML", "CWE-502", "high", ["python"], r"\byaml\.load\((?!.*Loader\s*=\s*(yaml\.)?C?SafeLoader)", "yaml.load without SafeLoader"),
    _r("PY-WEAK-HASH", "CWE-327", "medium", ["python"], r"\bhashlib\.(md5|sha1)\(", "weak hash algorithm (MD5/SHA-1)"),
    _r("PY-DEBUG", "CWE-489", "medium", ["python"], r"(\.run\(.*\bdebug\s*=\s*True|^\s*DEBUG\s*=\s*True)", "debug mode enabled"),
    _r("PY-TLS-VERIFY", "CWE-295", "medium", ["python"], r"\bverify\s*=\s*False", "TLS certificate verification disabled"),
    _r("PY-XSS-TEMPLATE", "CWE-79", "medium", ["python"], r"\b(render_template_string|Markup)\(|\|\s*safe\b", "unescaped HTML / template string rendering"),
    _r("PY-SEND-FILE", "CWE-22", "high", ["python"], r"\bsend_file\(.*(os\.path\.join|request\.|\+|f[\"'])", "send_file with a user-influenced path"),
    _r("PY-OPEN-USER", "CWE-22", "high", ["python"], r"\bopen\(.*request\.(args|form|values|files)", "open() on a request-controlled path"),
    _r("PY-JWT-NOVERIFY", "CWE-347", "high", ["python"], r"jwt\.decode\(.*(verify\s*=\s*False|verify_signature[\"']?\s*:\s*False)", "JWT decoded without signature verification"),
    _r("PY-WEAK-RANDOM", "CWE-338", "medium", ["python"], r"(token|password|secret|session|otp)\w*\s*=.*\brandom\.(random|randint|choice|choices|randrange)\(", "non-cryptographic random used for a secret"),
    _r("JS-EVAL", "CWE-95", "high", ["javascript", "typescript"], r"\beval\(|new Function\(", "eval / Function constructor"),
    _r("JS-INNERHTML", "CWE-79", "medium", ["javascript", "typescript"], r"\.innerHTML\s*=|dangerouslySetInnerHTML|document\.write\(", "DOM sink that can lead to XSS"),
    _r("JS-CMD-EXEC", "CWE-78", "high", ["javascript", "typescript"], r"child_process|\bexec(Sync)?\(", "shell command execution"),
    _r("JS-SQL-CONCAT", "CWE-89", "high", ["javascript", "typescript"], r"(query|execute)\(\s*[`\"'](select|insert|update|delete)[^`\"']*(\$\{|[\"'`]\s*\+)", "SQL built with string concatenation / template literal"),
    _r("JS-WEAK-RANDOM", "CWE-338", "medium", ["javascript", "typescript"], r"(token|secret|password|session)\w*\s*=.*Math\.random", "Math.random used for a secret"),
    _r("CFG-CORS-ANY", "CWE-942", "low", ["*"], r"access-control-allow-origin[\"']?\s*[:,=]\s*[\"']\*|CORS\(\s*app\s*\)", "CORS allows any origin"),
]


def scan_rules(rel: str, lang: str, lines: list[str]) -> list[Candidate]:
    rules = [r for r in RULES if lang in r.langs or "*" in r.langs]
    out = []
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "//", "*", "/*")):
            continue
        for r in rules:
            if r.rx.search(line):
                out.append(Candidate(rel, i, r.id, r.cwe, r.severity, r.message, stripped[:200]))
    return out


# --------------------------------------------------------------------------
# Secrets
# --------------------------------------------------------------------------
SECRET_PATTERNS = [
    ("SECRET-AWS-KEY", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key id"),
    ("SECRET-PRIVATE-KEY", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), "private key material"),
    ("SECRET-GITHUB-TOKEN", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), "GitHub token"),
    ("SECRET-SLACK-TOKEN", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "Slack token"),
    ("SECRET-STRIPE-KEY", re.compile(r"\b[sr]k_live_[0-9a-zA-Z]{16,}\b"), "Stripe live key"),
    ("SECRET-GOOGLE-KEY", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "Google API key"),
]
ASSIGN_RX = re.compile(
    r"""(?ix)\b([\w.\-]*(?:password|passwd|pwd|secret|api[_-]?key|apikey|token|auth[_-]?key|private[_-]?key|credential)[\w\-]*)["']?\s*[:=]\s*["']([^"'\n]{6,})["']"""
)
PLACEHOLDER = re.compile(r"(\$\{|\{\{|<[^>]+>|example|placeholder|your[_-]|xxxx|^\*+$|^\.+$)", re.I)


def shannon(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    return -sum(n / len(s) * math.log2(n / len(s)) for n in c.values())


def scan_secrets(rel: str, lines: list[str]) -> list[Candidate]:
    out = []
    for i, line in enumerate(lines, 1):
        for rid, rx, msg in SECRET_PATTERNS:
            if rx.search(line):
                out.append(Candidate(rel, i, rid, "CWE-798", "critical", f"Hardcoded credential: {msg}", line.strip()[:200], "secrets"))
        m = ASSIGN_RX.search(line)
        if m and not PLACEHOLDER.search(m.group(2)) and "environ" not in line and "getenv" not in line:
            sev = "critical" if len(m.group(2)) >= 20 and shannon(m.group(2)) >= 3.8 else "high"
            out.append(Candidate(rel, i, "SECRET-ASSIGN", "CWE-798", sev,
                                 f"Hardcoded credential assigned to '{m.group(1)}'", line.strip()[:200], "secrets"))
    return out


# --------------------------------------------------------------------------
# Python AST checks (more accurate than regex for SQLi / missing auth)
# --------------------------------------------------------------------------
SQL_WORDS = re.compile(r"\b(select|insert|update|delete|drop|where|from)\b", re.I)
SENSITIVE_ROUTE = re.compile(r"admin|delete|users?|export|reset|config|debug|internal|backup", re.I)
AUTH_HINT = re.compile(r"login_required|auth|require|jwt|token|permission|admin_only|roles?_|csrf", re.I)
AUTH_BODY = re.compile(r"\bsession\b|current_user|g\.user|request\.headers|abort\(\s*40[13]|Unauthorized|Forbidden")
ROUTE_ATTRS = {"route", "get", "post", "put", "delete", "patch"}


def _const(node) -> bool:
    try:
        ast.literal_eval(node)
        return True
    except Exception:
        return False


def _dynamic_sql(node) -> bool:
    """Expression builds a SQL-looking string from non-constant parts."""
    if _const(node):
        return False
    ok = (
        (isinstance(node, ast.JoinedStr) and any(isinstance(v, ast.FormattedValue) for v in node.values))
        or (isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)))
        or (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format")
    )
    if not ok:
        return False
    return any(isinstance(n, ast.Constant) and isinstance(n.value, str) and SQL_WORDS.search(n.value) for n in ast.walk(node))


def python_ast_checks(rel: str, source: str) -> list[Candidate]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    lines = source.splitlines()
    snippet = lambda n: lines[n - 1].strip()[:200] if 0 < n <= len(lines) else ""
    out: list[Candidate] = []

    scopes = [tree] + [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    for scope in scopes:
        dyn: dict[str, int] = {}
        for n in ast.walk(scope):
            if isinstance(n, ast.Assign) and _dynamic_sql(n.value):
                for t in n.targets:
                    if isinstance(t, ast.Name):
                        dyn[t.id] = n.lineno
            elif isinstance(n, ast.AugAssign) and isinstance(n.target, ast.Name) and _dynamic_sql(n.value):
                dyn[n.target.id] = n.lineno
        for n in ast.walk(scope):
            if not (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr.startswith("execute") and n.args):
                continue
            arg = n.args[0]
            if isinstance(arg, ast.Call) and getattr(arg.func, "id", getattr(arg.func, "attr", "")) == "text" and arg.args:
                arg = arg.args[0]
            if _dynamic_sql(arg):
                out.append(Candidate(rel, n.lineno, "PY-SQLI-AST", "CWE-89", "high",
                                     "SQL query built by string formatting/concatenation and executed", snippet(n.lineno), "ast"))
            elif isinstance(arg, ast.Name) and arg.id in dyn:
                out.append(Candidate(rel, n.lineno, "PY-SQLI-AST", "CWE-89", "high",
                                     f"Query variable '{arg.id}' (built by string formatting at line {dyn[arg.id]}) is executed",
                                     snippet(n.lineno), "ast"))

    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        path = None
        for d in fn.decorator_list:
            if isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute) and d.func.attr in ROUTE_ATTRS:
                if d.args and isinstance(d.args[0], ast.Constant):
                    path = str(d.args[0].value)
                    break
        if path is None or not SENSITIVE_ROUTE.search(path + " " + fn.name):
            continue
        deco_text = " ".join(ast.unparse(d) for d in fn.decorator_list if not (isinstance(d, ast.Call) and getattr(d.func, "attr", "") in ROUTE_ATTRS))
        body_text = ast.unparse(fn)
        if AUTH_HINT.search(deco_text) or AUTH_BODY.search(body_text):
            continue
        out.append(Candidate(rel, fn.lineno, "PY-ROUTE-NOAUTH", "CWE-306", "medium",
                             f"Route '{path}' looks sensitive but shows no authentication/authorization check", snippet(fn.lineno), "ast"))
    return out


# --------------------------------------------------------------------------
# Prompt-injection detection (the code under review is untrusted input)
# --------------------------------------------------------------------------
INJECTION_PATTERNS = [re.compile(p, re.I) for p in [
    r"ignore (all |any )?(the )?(previous|prior|above|earlier) (instructions|prompts|rules)",
    r"disregard (all |any )?(the )?(previous|prior|above|earlier|your) (instructions|prompts|rules)",
    r"you are now (a|an|in)\b",
    r"(do not|don't|never) (report|mention|flag) (any )?(vulnerabilit|issue|finding)",
    r"(report|reply|respond|answer|return)( with)?( that)? (no|zero|an empty) (vulnerabilit|finding|issue)",
    r"(note|message|instruction)s? (to|for) (the )?(ai|llm|assistant|model|reviewer|code reviewer|auditor)",
    r"(this|the) (file|code) (has been|was) (audited|reviewed|approved)",
    r"\bsystem prompt\b",
    r"<\|im_(start|end)\|>|\[/?INST\]",
]]


def detect_prompt_injection(rel: str, lines: list[str]) -> list[Candidate]:
    out, last = [], -10
    for i, line in enumerate(lines, 1):
        if any(p.search(line) for p in INJECTION_PATTERNS):
            if i - last <= 2:          # one finding per cluster of adjacent lines
                last = i
                continue
            last = i
            out.append(Candidate(rel, i, "INJECTION-ATTEMPT", "CWE-1427", "low",
                                 "Source text addresses an AI reviewer (possible prompt injection)", line.strip()[:200], "guard"))
    return out


_ESCAPE_RX = re.compile(r"<(/?)(untrusted_code|tool_output)", re.I)


def neutralize(text: str) -> str:
    """Stop code from closing/forging our data delimiters."""
    return _ESCAPE_RX.sub(r"<\1\2_escaped", text)


# --------------------------------------------------------------------------
# Dependencies + Bandit
# --------------------------------------------------------------------------
def check_dependencies(ws: Workspace) -> list[Candidate]:
    out = []
    for rel in ws.rels():
        if not re.search(r"requirements.*\.txt$", rel):
            continue
        for i, line in enumerate(ws.lines(rel), 1):
            s = line.strip()
            if s and not s.startswith(("#", "-")) and "==" not in s:
                out.append(Candidate(rel, i, "DEP-UNPINNED", "CWE-1104", "low", f"Unpinned dependency '{s}'", s, "deps"))
    return out


def run_bandit(ws: Workspace) -> list[Candidate]:
    """Optional extra static source. Returns [] if Bandit is not installed."""
    if not any(p.suffix == ".py" for p in ws.files()):
        return []
    try:
        import bandit  # noqa: F401
    except ImportError:
        return []
    target = str(ws.single or ws.root)
    cmd = [sys.executable, "-m", "bandit", "-r", target, "-f", "json", "-q"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        data = json.loads(proc.stdout or "{}")
    except Exception:
        return []
    out = []
    for r in data.get("results", []):
        if r.get("issue_severity", "LOW").upper() == "LOW":
            continue  # keep the baseline readable; LOW is mostly noise
        try:
            rel = Path(r["filename"]).resolve().relative_to(ws.root).as_posix()
        except ValueError:
            continue
        cwe = f"CWE-{r['issue_cwe']['id']}" if r.get("issue_cwe") else ""
        out.append(Candidate(rel, int(r["line_number"]), r["test_id"], cwe, r["issue_severity"].lower(),
                             r["issue_text"], (r.get("code") or "").strip().splitlines()[0][:200] if r.get("code") else "", "bandit"))
    return out


# --------------------------------------------------------------------------
# Aggregate
# --------------------------------------------------------------------------
def dedupe_candidates(cands: list[Candidate]) -> list[Candidate]:
    seen, out = set(), []
    for c in cands:
        key = (c.file, c.line, cwe_id(c) or c.rule_id)
        if key not in seen:
            seen.add(key)
            out.append(c)
    return sorted(out, key=lambda c: (c.file, c.line))


def scan_static(ws: Workspace, use_bandit: bool = True) -> list[Candidate]:
    cands: list[Candidate] = []
    for p in ws.files():
        rel, lang = ws.rel(p), ws.lang(p)
        lines = ws.lines(rel)
        cands += scan_secrets(rel, lines)           # specific patterns first so dedupe keeps them
        cands += scan_rules(rel, lang, lines)
        if lang == "python":
            cands += python_ast_checks(rel, ws.text(rel))
        cands += detect_prompt_injection(rel, lines)
    cands += check_dependencies(ws)
    if use_bandit:
        cands += run_bandit(ws)
    return dedupe_candidates(cands)
