"""Step 4: ask Gemini to fix the vulnerable files found by the scanner.

Needs:  pip install google-genai
        set GEMINI_API_KEY (or GOOGLE_API_KEY) in your environment
Optional: set GEMINI_MODEL to pick the model (default below).
"""
import os
import re
from collections import defaultdict
from pathlib import Path

MODEL = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")

RULES = {
    "SQLI": "Use parameterized queries (? placeholders with a params tuple). Never build SQL by concatenation or formatting.",
    "HARDCODED_SECRET": "Remove the literal. Read the value from an environment variable with os.environ[NAME] (no fallback literal).",
    "XSS": "Make sure user-controlled data is HTML-escaped when rendered. Remove |safe / Markup on untrusted data.",
    "IDOR": "Check that the record belongs to the logged-in user. If not, abort(404) (or 403). Keep owners able to read their own records.",
}


def _client():
    from google import genai
    return genai.Client()  # reads GEMINI_API_KEY / GOOGLE_API_KEY from the environment


def _strip_fences(text):
    m = re.search(r"```(?:python)?\n(.*?)```", text, re.S)
    return (m.group(1) if m else text).strip() + "\n"


def build_prompt(path, source, findings, test_source, previous_error=None):
    issues = "\n".join(f"- line {f['line']}: [{f['type']}] {f['why']}. Rule: {RULES[f['type']]}"
                       for f in findings)
    prompt = (
        "You are a secure-code fixer. Fix ONLY the security issues listed below in this file.\n"
        "Keep all existing behavior, routes, function names and imports that other files rely on.\n"
        "Return the COMPLETE corrected file and nothing else (no explanations).\n\n"
        f"File: {path}\n\nIssues:\n{issues}\n\n"
        f"Security tests that must pass after your fix:\n{test_source}\n\n"
        f"Current file:\n{source}\n"
    )
    if previous_error:
        prompt += f"\nYour previous attempt failed with:\n{previous_error}\nFix that too.\n"
    return prompt


def propose_fix(client, path, source, findings, test_source, previous_error=None):
    resp = client.models.generate_content(
        model=MODEL, contents=build_prompt(path, source, findings, test_source, previous_error))
    return _strip_fences(resp.text or "")


def apply_fixes(site, findings, test_path, previous_error=None):
    """Patch every file that has findings. Returns the list of files changed."""
    site = Path(site)
    test_source = Path(test_path).read_text(encoding="utf-8") if Path(test_path).exists() else ""
    by_file = defaultdict(list)
    for f in findings:
        by_file[f["file"]].append(f)
    client = _client()
    changed = []
    for rel, fs in by_file.items():
        target = site / rel
        source = target.read_text(encoding="utf-8")
        new = propose_fix(client, rel, source, fs, test_source, previous_error)
        try:
            compile(new, str(rel), "exec")  # refuse syntactically broken output
        except SyntaxError as e:
            print(f"[agent]   skipped {rel}: model returned invalid Python ({e.msg})")
            continue
        if new.strip() != source.strip():
            target.write_text(new, encoding="utf-8")
            changed.append(str(rel))
    return changed
