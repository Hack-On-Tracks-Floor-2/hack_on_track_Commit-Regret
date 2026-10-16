"""Generic client-side XSS candidates: ${...} interpolations that are not passed
through an escape function, in HTML/JS files that write HTML (innerHTML etc.)."""
import re
from pathlib import Path

SKIP = {"node_modules", ".venv", "venv", ".git", "__pycache__", "tests", "dist", "build"}
EXTS = {".html", ".htm", ".js", ".jsx", ".ts", ".tsx"}
SINK = re.compile(r"innerHTML|outerHTML|insertAdjacentHTML|document\.write|dangerouslySetInnerHTML")
INTERP = re.compile(r"\$\{([^}]*)\}")
SAFE = re.compile(r"^\s*\w*(esc|escape|sanitize|purify|encode)\w*\s*\(", re.I)
DATA = re.compile(r"[A-Za-z_]\w*\s*\.\s*[A-Za-z_]")
NUMERIC = re.compile(r"\bMath\.|\.(\w*_)?(id|length|count|size|index)\b")

def scan_web(site):
    out = []
    site = Path(site)
    for p in sorted(site.rglob("*")):
        if p.suffix.lower() not in EXTS:
            continue
        rel = p.relative_to(site)
        if any(part in SKIP for part in rel.parts):
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if not SINK.search(text):
            continue
        for n, line in enumerate(text.splitlines(), 1):
            for m in INTERP.finditer(line):
                expr = m.group(1).strip()
                if SAFE.match(expr) or not DATA.search(expr) or NUMERIC.search(expr):
                    continue
                out.append({"type": "XSS", "file": rel.as_posix(), "line": n,
                            "why": f"unescaped ${{{expr[:60]}}} in a file that writes HTML",
                            "rule": "webscan-unescaped-interpolation", "tool": "webscan"})
    return out[:25]
