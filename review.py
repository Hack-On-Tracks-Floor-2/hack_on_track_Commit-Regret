import os
from pathlib import Path
from fixloop import ask_json, SKIP

LIMIT = int(os.environ.get("REVIEW_LIMIT", "40000"))
CLASSES = "sqli, xss, idor, secret, cmdi"


def numbered_source(site):
    files = [p for p in Path(site).rglob("*")
             if p.is_file() and p.suffix in {".py", ".html", ".js"}
             and not (set(p.parts) & SKIP)
             and not any(x in ("tests", "test") for x in p.parts)
             and not p.name.startswith("test_")]
    files.sort(key=lambda p: (p.suffix != ".py", str(p)))
    out, total = [], 0
    for p in files:
        lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()
        text = "\n".join(f"{i}: {l}" for i, l in enumerate(lines, 1))
        if total + len(text) > LIMIT:
            out.append(f"--- {p.relative_to(site)} (skipped: size limit) ---")
            continue
        out.append(f"--- {p.relative_to(site)} ---\n{text}")
        total += len(text)
    return "\n".join(out)


def review_site(site, scanner_findings):
    listing = "\n".join(
        f"[{i}] {f.get('vuln_class') or f.get('class') or f.get('type')} {f.get('file')}:{f.get('line')}"
        for i, f in enumerate(scanner_findings))
    r = ask_json(f"""You are a security reviewer. Review this web app source (lines are numbered).
Vulnerability classes to look for: {CLASSES}.
1) For each scanner finding below, decide if it is a REAL exploitable vulnerability: trace whether
user-controlled input reaches the dangerous operation without safe handling. Parameterized queries,
constants and escaped output are NOT vulnerabilities.
2) Find additional real vulnerabilities the scanner missed. IDOR means an object (record, note, account,
payment) is fetched or modified by id without checking it belongs to the current user. Stored XSS means
user-supplied text is saved and later rendered unescaped (|safe, Markup, innerHTML, HTML built from strings).
Only report issues you can point to in the code, using the exact file and line number from the numbering.
SCANNER FINDINGS:
{listing or 'none'}
SOURCE:
{numbered_source(site)}
Return JSON: {{"verdicts": [{{"index": 0, "real": true, "reason": "..."}}],
"new_findings": [{{"vuln_class": "xss|idor|sqli|secret|cmdi", "file": "path", "line": 0, "explanation": "..."}}]}}""")
    verdicts = {v.get("index"): v for v in r.get("verdicts", []) if isinstance(v, dict)}
    kept, dropped = [], []
    for i, f in enumerate(scanner_findings):
        v = verdicts.get(i)
        if v is not None and v.get("real") is False:
            dropped.append((f, v.get("reason", "")))
        else:
            kept.append(f)
    new = [n for n in r.get("new_findings", []) if isinstance(n, dict) and n.get("file")]
    return kept, new, dropped