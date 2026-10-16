"""Step A (Detect candidates): run Semgrep, Bandit and detect-secrets and return
one merged list of candidate findings.

Each finding: {type, file, line, snippet, why, tools, rule}
type is one of SQLI, HARDCODED_SECRET, XSS, IDOR, OTHER.
A tool that is missing or fails is skipped and reported, it never stops the run.
"""
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

SKIP_PARTS = {"tests", ".venv", "venv", "__pycache__", ".git", "node_modules", "site-packages"}


def _run(cmd, cwd, timeout=300):
    env = dict(os.environ, PYTHONUTF8="1", PYTHONIOENCODING="utf-8")
    try:
        p = subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=timeout, env=env)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", "not installed"
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"


def _classify(text):
    t = text.lower()
    if "sql" in t:
        return "SQLI"
    if any(k in t for k in ("xss", "cross-site", "autoescape", "render_template_string",
                            "mark_safe", "markupsafe", "unescaped", "|safe", "jinja2")):
        return "XSS"
    if any(k in t for k in ("secret", "hardcoded", "hard-coded", "password", "token", "api key",
                            "api_key", "credential")):
        return "HARDCODED_SECRET"
    if any(k in t for k in ("idor", "insecure direct object", "authorization", "access control")):
        return "IDOR"
    return "OTHER"


def _norm(path):
    return Path(os.path.normpath(path.replace("\\", "/"))).as_posix()


def _skip(rel):
    p = Path(rel)
    return (any(part in SKIP_PARTS for part in p.parts)
            or p.name.startswith("test_") or p.name == "conftest.py")


def _snippet(site, rel, line):
    try:
        lines = (Path(site) / rel).read_text(encoding="utf-8", errors="ignore").splitlines()
        return lines[line - 1].strip() if 0 < line <= len(lines) else ""
    except OSError:
        return ""


def _first_sentence(text, limit=160):
    text = " ".join((text or "").split())
    return text[:limit] + ("..." if len(text) > limit else "")


# ---- parsers (take the tool's JSON, return raw findings) -------------------

def parse_semgrep(data):
    out = []
    for r in data.get("results", []):
        extra = r.get("extra", {})
        rule = r.get("check_id", "")
        why = _first_sentence(extra.get("message", rule))
        out.append({"type": _classify(rule + " " + why), "file": _norm(r["path"]),
                    "line": r["start"]["line"], "why": why, "rule": rule, "tool": "semgrep"})
    return out


BANDIT_TYPES = {"B608": "SQLI", "B105": "HARDCODED_SECRET", "B106": "HARDCODED_SECRET",
                "B107": "HARDCODED_SECRET", "B703": "XSS", "B704": "XSS", "B308": "XSS"}


def parse_bandit(data):
    out = []
    for r in data.get("results", []):
        tid = r.get("test_id", "")
        why = _first_sentence(r.get("issue_text", ""))
        out.append({"type": BANDIT_TYPES.get(tid) or _classify(r.get("test_name", "") + " " + why),
                    "file": _norm(r["filename"]), "line": r["line_number"],
                    "why": why, "rule": f"{tid} {r.get('test_name', '')}".strip(), "tool": "bandit"})
    return out


def parse_detect_secrets(data):
    out = []
    for path, items in data.get("results", {}).items():
        for it in items:
            out.append({"type": "HARDCODED_SECRET", "file": _norm(path), "line": it["line_number"],
                        "why": f"possible secret in source ({it.get('type', 'secret')})",
                        "rule": it.get("type", "secret"), "tool": "detect-secrets"})
    return out


# ---- runners ---------------------------------------------------------------

def _json_or_error(out, err):
    try:
        return json.loads(out), None
    except (ValueError, TypeError):
        lines = (err or "").strip().splitlines()
        return None, (lines[-1] if lines else "no output")


def run_semgrep(site):
    exe = shutil.which("semgrep")
    if not exe:
        return [], "skipped (semgrep not found)"
    _, out, err = _run([exe, "--config", "p/python", "--config", "p/flask", "--config", "p/secrets",
                        "--json", "--quiet", "--metrics=off", "."], site)
    data, problem = _json_or_error(out, err)
    if data is None:
        return [], f"failed: {problem}"
    return parse_semgrep(data), "ok"


def run_bandit(site):
    code, out, err = _run([sys.executable, "-m", "bandit", "-r", ".", "-f", "json", "-q",
                           "-x", "./tests,./.venv,./venv"], site)
    if "No module named bandit" in err:
        return [], "skipped (run: pip install bandit)"
    data, problem = _json_or_error(out, err)
    if data is None:
        return [], f"failed: {problem}"
    return parse_bandit(data), "ok"


def run_detect_secrets(site):
    _, out, err = _run([sys.executable, "-m", "detect_secrets", "scan", "--all-files", "."], site)
    if "No module named" in err:
        return [], "skipped (run: pip install detect-secrets)"
    data, problem = _json_or_error(out, err)
    if data is None:
        return [], f"failed: {problem}"
    return parse_detect_secrets(data), "ok"


def run_builtin(site):
    from scanner import scan_site
    out = [{"type": f["type"], "file": _norm(f["file"]), "line": f["line"], "why": f["why"],
            "rule": "builtin", "tool": "builtin"} for f in scan_site(site)]
    return out, "ok"


# ---- merge -----------------------------------------------------------------

def merge(findings):
    findings = sorted(findings, key=lambda f: (f["file"], f["type"], f["line"]))
    merged = []
    for f in findings:
        slack = 0 if f["type"] == "OTHER" else 3
        for m in merged:
            if m["file"] == f["file"] and m["type"] == f["type"] and abs(m["line"] - f["line"]) <= slack:
                if f["tool"] not in m["tools"]:
                    m["tools"].append(f["tool"])
                break
        else:
            merged.append(dict(f, tools=[f["tool"]]))
    return merged


def detect(site):
    """Returns (merged findings, {tool name: status})."""
    raw, status = [], {}
    for name, fn in (("semgrep", run_semgrep), ("bandit", run_bandit),
                     ("detect-secrets", run_detect_secrets), ("builtin", run_builtin)):
        found, state = fn(site)
        found = [f for f in found if not _skip(f["file"])]
        status[name] = f"{state}, {len(found)} finding(s)" if state == "ok" else state
        raw += found
    merged = merge(raw)
    for f in merged:
        f["snippet"] = _snippet(site, f["file"], f["line"])
    return merged, status


if __name__ == "__main__":
    from tools import discover_sites
    for site in discover_sites(sys.argv[1]):
        findings, status = detect(site)
        print(f"== {site.name}")
        for tool, s in status.items():
            print(f"  [{tool}] {s}")
        for f in findings:
            print(f"  -> {f['type']:<16} {f['file']}:{f['line']:<4} by {', '.join(f['tools'])}")
            print(f"       {f['snippet']}")