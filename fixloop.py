import os, re, json, time
from pathlib import Path
from tools import run

MAX_TRIES = 5
SEC = "_security"
SKIP = {".git", "__pycache__", ".venv", "venv", "node_modules", ".pytest_cache", SEC}
MODEL = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
FALLBACKS = [m for m in os.environ.get("GEMINI_FALLBACKS", "").split(",") if m]
GROQ_MODEL = os.environ.get("GROQ_MODEL", "openai/gpt-oss-120b")
MIN_GAP = float(os.environ.get("GEMINI_MIN_GAP", "6"))
BUNDLE_LIMIT = int(os.environ.get("BUNDLE_LIMIT", "20000"))
CONTEXT_CHARS = int(os.environ.get("CONTEXT_CHARS", "14000"))
CLIENT_EXT = (".html", ".htm", ".js", ".jsx", ".ts", ".tsx")
_client = None
_last_call = [0.0]

PLAYBOOK = {
 "sqli": "Use parameterized queries (placeholders + a values tuple). Same DB library. Never escape or blacklist characters.",
 "xss": "Make user content escaped on output. In templates: remove |safe / Markup(), rely on autoescape. If the unsafe sink is client-side (innerHTML or a template literal in an HTML/JS file), fix it in that file: wrap the value in the file's existing escape helper (add a small one if none exists). Do not strip characters on input and do not HTML-escape data inside the API.",
 "idor": "Add an ownership check in the query or handler (e.g. WHERE id=? AND owner=?). Return 404 (or 403) for other users' objects.",
 "cmdi": "Never use a shell. Use subprocess.run([...]) with an argument list, and validate input against an allow-list.",
 "secret": "Read the value from os.environ[...] with NO fallback to the old literal. Add .env.example with a placeholder and add .env to .gitignore. If tests need the variable, set it in conftest.py.",
 "other": "Make the smallest root-cause fix.",
}


def _clean_json(text):
    t = text.strip().strip("`")
    if t.lower().startswith("json"):
        t = t[4:]
    return json.loads(t)


def _unescape(code):
    """Some models double-escape code inside JSON: literal backslash-n instead of newlines."""
    if code.count("\n") < 3 and "\\n" in code:
        code = code.replace("\\n", "\n").replace('\\"', '"').replace("\\t", "\t")
    return code


def _gap():
    gap = time.time() - _last_call[0]
    if gap < MIN_GAP:
        time.sleep(MIN_GAP - gap)
    _last_call[0] = time.time()


# ---------- LLM helpers ----------
def ask_groq(prompt):
    from groq import Groq
    client = Groq()
    last = None
    for attempt in range(4):
        _gap()
        try:
            r = client.chat.completions.create(
                model=GROQ_MODEL, messages=[{"role": "user", "content": prompt}],
                response_format={"type": "json_object"}, temperature=0.2)
            text = r.choices[0].message.content
            if not text:
                last = RuntimeError("empty reply")
                continue
            return _clean_json(text)
        except json.JSONDecodeError as e:
            last = e
        except Exception as e:
            last = e
            msg = str(e)
            if "429" in msg or "rate" in msg.lower():
                if "day" in msg.lower():
                    break
                wait = 10 * (attempt + 1)
                print(f"   (Groq rate limit, waiting {wait}s)", flush=True)
                time.sleep(wait)
                continue
            raise
    raise RuntimeError(f"Groq failed: {last}")


def ask_json(prompt):
    global _client
    if not (os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")):
        raise RuntimeError("GEMINI_API_KEY is not set in this terminal window")
    from google import genai
    from google.genai import errors
    _client = _client or genai.Client()
    models = [MODEL] + [m for m in FALLBACKS if m != MODEL]
    last = None
    for mi, model in enumerate(models):
        thinking_off, busy = True, 0
        for attempt in range(6):
            _gap()
            cfg = {"response_mime_type": "application/json", "max_output_tokens": 8192}
            if thinking_off:
                cfg["thinking_config"] = {"thinking_budget": 0}
            try:
                r = _client.models.generate_content(model=model, contents=prompt, config=cfg)
                text = r.text
                if not text:
                    last = RuntimeError("empty reply")
                    print("   (Gemini returned an empty reply; retrying)", flush=True)
                    continue
                return _clean_json(text)
            except errors.APIError as e:
                last = e
                msg = str(e)
                code = getattr(e, "code", None)
                if code == 400 and "thinking" in msg.lower() and thinking_off:
                    thinking_off = False
                    continue
                if code == 404:
                    print(f"   (model '{model}' not found for this key; skipping)", flush=True)
                    break
                if code == 429 and ("PerDay" in msg or "per day" in msg.lower()):
                    print(f"   (daily quota used up for {model})", flush=True)
                    break
                if code in (429, 500, 503, 504):
                    busy += 1
                    if busy >= 2 and mi < len(models) - 1:
                        print(f"   ({model} busy, switching to next model)", flush=True)
                        break
                    m = re.search(r"retry in ([\d.]+)s|'retryDelay': '(\d+)s'", msg)
                    wait = float(m.group(1) or m.group(2)) + 2 if m else 10 * busy
                    wait = min(wait, 40)
                    print(f"   (Gemini {code} on {model}: waiting {wait:.0f}s)", flush=True)
                    time.sleep(wait)
                    continue
                raise
            except json.JSONDecodeError as e:
                last = e
    raise RuntimeError(f"Gemini failed: {last}")


# ---------- finding helpers ----------
def klass(c):
    c = (c or "").lower()
    for key, names in (("sqli", ("sql",)), ("secret", ("secret", "hardcode", "credential")),
                       ("xss", ("xss", "script")), ("idor", ("idor", "access", "authoriz", "object")),
                       ("cmdi", ("command", "cmdi", "shell"))):
        if any(n in c for n in names):
            return key
    return "other"


def norm(f):
    return {"cls": klass(f.get("vuln_class") or f.get("class") or f.get("type")),
            "file": f.get("file", ""), "line": f.get("line", 0),
            "why": f.get("explanation") or f.get("reason") or f.get("message") or f.get("why") or "",
            "snippet": f.get("snippet", "")}


def where(f):
    s = f"{f['cls']} near {f['file']}:{f['line']}. {f['why']}"
    if f.get("snippet"):
        s += f"\nFlagged line: {f['snippet']}"
    return s


def is_client(f):
    return str(f.get("file", "")).lower().endswith(CLIENT_EXT)


def _line(f):
    try:
        return int(f.get("line", 0))
    except Exception:
        return 0


def _source_files(site):
    site = Path(site)
    return [p for p in site.rglob("*") if p.is_file()
            and p.suffix in {".py", ".html", ".txt", ".js"}
            and not (set(p.relative_to(site).parts) & SKIP)]


def bundle(site, limit=None):
    """Whole-project text, capped. Truncates a big file instead of dropping everything."""
    limit, site = limit or BUNDLE_LIMIT, Path(site)
    files = _source_files(site)
    files.sort(key=lambda p: ("test" in p.relative_to(site).as_posix().lower(), p.as_posix()))
    out, total = [], 0
    for p in files:
        room = limit - total
        if room < 500:
            break
        t = p.read_text(encoding="utf-8", errors="ignore")
        if len(t) > room:
            t = t[:room] + "\n... (file truncated)"
        out.append(f"--- {p.relative_to(site).as_posix()} ---\n{t}")
        total += len(t)
    return "\n".join(out)


def test_template(site, chars=2500):
    """The repo's own test setup (imports + client fixture), so exploit tests copy a working pattern."""
    site = Path(site)
    cands = sorted(site.rglob("conftest.py")) + sorted(site.rglob("test_*.py"))
    cands = [p for p in cands if not (set(p.relative_to(site).parts) & SKIP)]
    out = []
    for p in cands[:2]:
        t = p.read_text(encoding="utf-8", errors="ignore")[:chars]
        out.append(f"--- EXISTING TEST SETUP: {p.relative_to(site).as_posix()} (start of file) ---\n{t}")
    return "\n".join(out)


def context(site, f, with_tests=True):
    """Focused code for one finding: the flagged file (whole if small, else head + window) plus test setup."""
    site, parts = Path(site), []
    p = site / f["file"]
    if p.is_file():
        text = p.read_text(encoding="utf-8", errors="ignore")
        if len(text) <= CONTEXT_CHARS:
            parts.append(f"--- {f['file']} ---\n{text}")
        else:
            lines, ln = text.splitlines(), _line(f)
            lo, hi = max(40, ln - 60), min(len(lines), ln + 60)
            parts.append(f"--- {f['file']} (first 40 lines) ---\n" + "\n".join(lines[:40]))
            parts.append(f"--- {f['file']} (lines {lo + 1}-{hi}) ---\n" + "\n".join(lines[lo:hi]))
    else:
        parts.append(bundle(site))
    if with_tests:
        parts.append(test_template(site))
    return "\n".join(x for x in parts if x)


# ---------- test helpers ----------
def pytest(site, py, args):
    return run([py, "-m", "pytest", "-q", *args], cwd=site)


def last_line(out):
    ls = [l for l in out.strip().splitlines() if l.strip()]
    return ls[-1] if ls else ""


def suite(site, py):
    code, out = pytest(site, py, [f"--ignore={SEC}"])
    return code == 0, out


def commit(site, msg):
    run(["git", "add", "-A"], cwd=site)
    run(["git", "-c", "user.name=agent", "-c", "user.email=agent@local", "commit", "-m", msg], cwd=site)


# ---------- baseline tests when the repo has none ----------
def generate_baseline_tests(site, py):
    d = Path(site) / "tests"
    d.mkdir(exist_ok=True)
    feedback = ""
    for _ in range(3):
        r = ask_json(f"""Write ONE pytest file that records the CURRENT legitimate behavior of this Flask app,
so we can detect regressions after a security fix.
Rules: use Flask's test client and create the app the way run.py / the app package does, without starting a server.
Import only names that exist in SOURCE. If the app writes to a database, avoid changing shared data (use a temp or in-memory DB if the code allows it).
Write 6-10 tests of NORMAL behavior only: pages load, valid login works, invalid login is rejected,
a normal search returns expected results, role access as it works today.
No attack payloads, no network. Every test must PASS on the current code.
{feedback}
SOURCE:
{bundle(site)}
Return JSON: {{"test_code": "<python source>"}}""")
        (d / "test_baseline.py").write_text(_unescape(r["test_code"]), encoding="utf-8")
        rc, out = pytest(site, py, ["tests/test_baseline.py"])
        if rc == 0:
            commit(site, "baseline tests (agent-generated)")
            return True
        feedback = "Your tests failed on the current code. Fix them:\n" + out[-1500:]
    return False


# ---------- reproduce ----------
CLIENT_HINT = ("The flagged code is in an HTML/JS file, so pytest cannot run a browser. Write a SOURCE-LEVEL test: "
               "read that file as text (Path(__file__).resolve().parent.parent / '<relative path>') and assert that the "
               "flagged interpolation is wrapped in an escape function call (use a regex on the file text). "
               "It must FAIL on the current text and PASS once the value is escaped.")


def make_exploit(site, py, f, n):
    """Returns (path, reason). path is None when no usable test was produced."""
    feedback, passed = "", 0
    hint = CLIENT_HINT if is_client(f) else (
        "Assert on SECURE behavior (injection payload returns no extra rows; another user's object is not readable; "
        "stored script comes back escaped, using one request to store and another to render; for an auth bypass, "
        "the secret code no longer grants access). Log in first if the route needs it.")
    d = Path(site) / SEC
    d.mkdir(exist_ok=True)
    path = d / f"test_exploit_{n}.py"
    for k in range(3):
        r = ask_json(f"""Write ONE pytest file for this project.
Vulnerability: {where(f)}
It must PASS only when the code is secure and FAIL with an AssertionError while the bug exists.
Copy the imports and the client fixture from EXISTING TEST SETUP below. Import only names that exist in SOURCE;
do NOT invent app factories, models or fixtures. No network.
{hint}
{feedback}
SOURCE:
{context(site, f)}
Return JSON: {{"test_code": "<python source>"}}""")
        path.write_text(_unescape(r["test_code"]), encoding="utf-8")
        rc, out = pytest(site, py, [f"{SEC}/{path.name}"])
        print(f"   exploit attempt {k + 1}: pytest exit code {rc}", flush=True)
        if rc not in (0, 1):
            print(out[-500:], flush=True)
        if rc == 1 and re.search(r"^E\s+assert|AssertionError", out, re.M):
            return path, ""
        if rc == 0:
            passed += 1
            if passed >= 2:
                path.unlink(missing_ok=True)
                return None, "exploit test passes on current code, likely not exploitable"
        feedback = f"Your last test did not fail cleanly on the vulnerable code (exit {rc}):\n{out[-1200:]}"
    path.unlink(missing_ok=True)
    return None, "no working exploit"


# ---------- patch ----------
def restore(backup):
    for p, orig in backup.items():
        if orig is None:
            p.unlink(missing_ok=True)
        else:
            p.write_text(orig, encoding="utf-8")


def apply_edits(site, edits, py):
    site, backup = Path(site).resolve(), {}
    try:
        for e in edits:
            rel = e["file"].replace("\\", "/")
            p = (site / rel).resolve()
            parts = Path(rel).parts
            if site not in p.parents:
                raise ValueError(f"{rel} is outside the site folder")
            if SEC in parts or "tests" in parts or Path(rel).name.startswith("test_"):
                raise ValueError("test files are off limits")
            if p not in backup:
                backup[p] = p.read_text(encoding="utf-8") if p.exists() else None
            old, new = e.get("old", ""), e["new"]
            if p.exists() and old:
                text = p.read_text(encoding="utf-8")
                if text.count(old) != 1:
                    raise ValueError(f"'old' must match exactly once in {rel}, found {text.count(old)}")
                p.write_text(text.replace(old, new), encoding="utf-8")
            elif not old:
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text((p.read_text(encoding="utf-8") + "\n" if p.exists() else "") + new, encoding="utf-8")
            else:
                raise ValueError(f"{rel} does not exist")
        for p in backup:
            if p.suffix == ".py" and p.exists():
                rc, out = run([py, "-m", "py_compile", str(p)])
                if rc:
                    raise ValueError("syntax error: " + out[-300:])
        return backup
    except Exception:
        restore(backup)
        raise


def secret_value(site, f):
    try:
        line = (Path(site) / f["file"]).read_text(encoding="utf-8").splitlines()[int(f["line"]) - 1]
    except Exception:
        return None
    m = re.search(r"""["']([^"']{8,})["']""", line)
    return m.group(1) if m else None


def secret_gone(site, val):
    for p in Path(site).rglob("*"):
        if p.is_file() and not (set(p.parts) & SKIP):
            if val in p.read_text(encoding="utf-8", errors="ignore"):
                return False
    return True


# ---------- one finding ----------
def fix_one(site, py, f, n):
    res = {"n": n, "cls": f["cls"], "where": f"{f['file']}:{f['line']}", "status": "", "tries": 0,
           "before": "", "after": "", "tests": "", "diff": ""}
    exploit, secret = None, None
    client = is_client(f)
    if f["cls"] == "secret":
        secret = secret_value(site, f)
        if not secret:
            res["status"] = "UNCONFIRMED"
            return res
        res["before"] = "secret found in source"
        proof_text = "Proof: the secret literal must not appear anywhere in the source."
    else:
        exploit, why_not = make_exploit(site, py, f, n)
        if not exploit:
            res["status"] = f"UNCONFIRMED ({why_not})"
            return res
        res["before"] = "unescaped output in source (source-level check fails)" if client else "exploit succeeds"
        proof_text = "Test that must pass after the fix:\n" + exploit.read_text(encoding="utf-8")

    feedback = ""
    for attempt in range(1, MAX_TRIES + 1):
        res["tries"] = attempt
        try:
            r = ask_json(f"""Fix this vulnerability with a minimal root-cause patch.
{where(f)}
Fix rules: {PLAYBOOK[f['cls']]}
Do not edit test files, do not add dependencies, keep behavior for legitimate requests.
{proof_text}
Previous attempt failed: {feedback or 'none'}
SOURCE:
{context(site, f, with_tests=False)}
Return JSON: {{"edits": [{{"file": "relative/path", "old": "exact existing text, or empty to create/append", "new": "replacement"}}]}}""")
            backup = apply_edits(site, r["edits"], py)
        except Exception as e:
            feedback = f"Edit rejected: {e}"
            continue
        ok, out = suite(site, py)
        proof, pout = False, ""
        if ok:
            if exploit:
                rc, pout = pytest(site, py, [f"{SEC}/{exploit.name}"])
                proof = rc == 0
            else:
                proof, pout = secret_gone(site, secret), "secret literal still present"
        if ok and proof:
            after = "removed from source" if secret else ("escaped in source" if client else "blocked")
            res.update(status="FIXED", after=after, tests=last_line(out),
                       diff=run(["git", "diff"], cwd=site)[1])
            commit(site, f"fix: {f['cls']} in {f['file']}")
            return res
        feedback = ("Existing tests failed:\n" + out[-1500:]) if not ok else ("Fix did not stop the exploit:\n" + pout[-1500:])
        restore(backup)
    res["status"] = "NEEDS HUMAN"
    return res


# ---------- one site ----------
def fix_site(site, py, findings):
    results, seen = [], set()
    for i, raw in enumerate(findings, 1):
        f = norm(raw)
        key = (f["cls"], f["file"], f["line"])
        if key in seen:
            continue
        seen.add(key)
        print(f"[{Path(site).name}] #{i} {f['cls']} {f['file']}:{f['line']} ...", flush=True)
        try:
            r = fix_one(site, py, f, i)
        except Exception as e:
            r = {"n": i, "cls": f["cls"], "where": f"{f['file']}:{f['line']}",
                 "status": f"ERROR: {str(e)[:80]}", "tries": 0,
                 "before": "", "after": "", "tests": "", "diff": ""}
        r["site"] = Path(site).name
        print(f"   -> {r['status']} (tries: {r['tries']})", flush=True)
        results.append(r)
    if list((Path(site) / SEC).glob("test_*.py")):
        rc, out = pytest(site, py, [SEC])
        print(f"[{Path(site).name}] final: all exploit tests {'PASS' if rc == 0 else 'FAIL'}", flush=True)
    return results


# ---------- report ----------
def write_report(results, path="report.md"):
    L = ["# Vulnerability fix report", "",
         "| Site | # | Class | Location | Status | Tries | Before | After | Tests |",
         "|---|---|---|---|---|---|---|---|---|"]
    for r in results:
        L.append(f"| {r['site']} | {r['n']} | {r['cls']} | {r['where']} | {r['status']} | "
                 f"{r['tries']} | {r['before']} | {r['after']} | {r['tests']} |")
    for r in results:
        if r["diff"]:
            L += ["", f"## {r['site']} #{r['n']} ({r['cls']})", "", "```diff", r["diff"], "```"]
    Path(path).write_text("\n".join(L), encoding="utf-8")