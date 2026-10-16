"""Static scanner: finds suspected vulnerabilities in a site's Python code.

Returns a list of findings:
  {"type", "file", "line", "snippet", "why"}
Types: SQLI, HARDCODED_SECRET, XSS, IDOR
"""
import ast
import re
from pathlib import Path

SKIP_DIRS = {".venv", "venv", "__pycache__", ".git", "tests", "node_modules"}
SECRET_NAME = re.compile(r"(secret|token|password|passwd|api_?key|private_?key)", re.I)
SQL_CALL = re.compile(r"\.(execute|executemany|executescript)\s*\(")


def py_files(site):
    for p in Path(site).rglob("*.py"):
        if SKIP_DIRS.isdisjoint(p.parts) and p.name != "conftest.py":
            yield p


def finding(kind, path, line, snippet, why):
    return {"type": kind, "file": str(path), "line": line,
            "snippet": snippet.strip(), "why": why}


def scan_lines(path, text):
    out = []
    lines = text.splitlines()
    for i, line in enumerate(lines, 1):
        # --- SQL injection: execute(...) built with +, f-string, % or .format
        window = " ".join(lines[i - 1:i + 2])
        if SQL_CALL.search(line):
            if re.search(r'["\']\s*\+|\+\s*["\']|f["\']|%\s*\(|["\']\s*%|\.format\(', window):
                out.append(finding("SQLI", path, i, line,
                                   "SQL string built from variables instead of ? placeholders"))
        # --- Hardcoded secret: NAME = "literal"
        m = re.match(r'\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*["\']([^"\']{8,})["\']', line)
        if m and SECRET_NAME.search(m.group(1)) and "environ" not in line and "getenv" not in line:
            out.append(finding("HARDCODED_SECRET", path, i, line,
                               f"{m.group(1)} is a literal in source code"))
        # --- XSS: |safe, Markup(), autoescape off
        if re.search(r"\|\s*safe\b|\bMarkup\s*\(|autoescape\s+false", line, re.I):
            out.append(finding("XSS", path, i, line,
                               "output marked safe, so user data is not HTML-escaped"))
    return out


def scan_idor(path, text):
    """Route has an id parameter, selects by that id, but never checks the owner/user."""
    out = []
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return out
    for fn in ast.walk(tree):
        if not isinstance(fn, ast.FunctionDef):
            continue
        routed = any(isinstance(d, ast.Call) and getattr(d.func, "attr", "") == "route"
                     for d in fn.decorator_list)
        id_args = [a.arg for a in fn.args.args if a.arg.endswith("id")]
        if not (routed and id_args):
            continue
        src = ast.get_source_segment(text, fn) or ""
        selects_by_id = re.search(r"select .* where\s+id\s*=", src, re.I | re.S)
        checks_owner = re.search(r"owner|user_id|current_user|session\[", src, re.I)
        # current_user() used only as a login gate is not an ownership check
        if selects_by_id and not re.search(r"owner\s*=|owner\s*!=|\[\s*\d\s*\]\s*[!=]=\s*(user|current)", src, re.I):
            out.append(finding("IDOR", path, fn.lineno, f"def {fn.name}(...)",
                               f"loads a record by {id_args[0]} without checking it belongs to the caller"))
    return out


def scan_site(site):
    findings = []
    for p in py_files(site):
        text = p.read_text(encoding="utf-8", errors="ignore")
        rel = p.relative_to(site)
        findings += scan_lines(rel, text)
        findings += scan_idor(rel, text)
    return findings


if __name__ == "__main__":
    import sys
    from tools import discover_sites
    for site in discover_sites(sys.argv[1]):
        print(f"== {site.name}")
        for f in scan_site(site):
            print(f"  [{f['type']}] {f['file']}:{f['line']}  {f['why']}")