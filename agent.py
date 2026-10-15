"""
Very basic security-fix agent.

Steps:
  1. RUN TESTS   - baseline, make sure the suite passes before we touch anything
  2. LOCATE      - scan .py files for SQL injection + hardcoded secrets
  3. EXPLOIT     - prove the SQL injection works (before)
  4. PATCH       - parameterize SQL, move secrets to environment variables
  5. RE-TEST     - run the same tests again, and re-run the exploit (after)

Usage:  python agent.py path/to/vitalcare1
"""
import os
import re
import shutil
import subprocess
import sys

# ---------- 1. what we look for ----------------------------------------------
# SQL built by gluing strings:   "... LIKE '%" + term + "%' ..."
SQLI_RE = re.compile(r"""['"]\s*\+\s*\w+\s*\+\s*['"]""")
# Secrets written in code:   SECRET_KEY="abc123"
SECRET_RE = re.compile(
    r"""^\s*(SECRET_KEY|ADMIN_OVERRIDE_PASSWORD|INSURANCE_API_KEY)\s*=\s*(["'])(.+?)\2\s*,?\s*$"""
)

# Secrets the tests rely on -> supplied through the *environment* when testing
TEST_ENV = {"ADMIN_OVERRIDE_PASSWORD": "override-2024"}


def py_files(root):
    for folder, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in (".venv", "__pycache__", "tests", ".git")]
        for f in files:
            if f.endswith(".py"):
                yield os.path.join(folder, f)


def locate(root):
    findings = []
    for path in py_files(root):
        for n, line in enumerate(open(path, encoding="utf-8"), 1):
            if SQLI_RE.search(line):
                findings.append(("SQL injection", path, n, line.strip()))
            if SECRET_RE.match(line):
                findings.append(("Hardcoded secret", path, n, line.strip()))
    return findings


# ---------- 2. the patches ---------------------------------------------------
def patch_sqli(path):
    src = open(path, encoding="utf-8").read()
    # the whole  query = ( "..." + term + "..." )  block, plus the execute() call
    block = re.compile(r"query = \(\n(?:.*\+.*\n|.*\n)*?\s*\)\n(\s*)patients = db\.execute\(query\)")
    new = (
        'query = (\n'
        '        "SELECT id, full_name, mrn, department FROM patients "\n'
        '        "WHERE full_name LIKE ? OR mrn LIKE ? ORDER BY full_name"\n'
        '    )\n'
        '    like = "%" + term + "%"   # user input is now DATA, never SQL\n'
        '    patients = db.execute(query, (like, like))'
    )
    out, count = block.subn(new, src)
    if count:
        open(path, "w", encoding="utf-8").write(out)
    return count


def patch_secrets(path):
    lines = open(path, encoding="utf-8").read().splitlines(keepends=True)
    changed = 0
    for i, line in enumerate(lines):
        m = SECRET_RE.match(line)
        if m:
            name = m.group(1)
            indent = line[: len(line) - len(line.lstrip())]
            # no hardcoded fallback. If the env var is missing, use a random value
            # (NOT an empty string - "" == "" would let a blank password into /admin)
            lines[i] = f'{indent}{name}=os.environ.get("{name}") or os.urandom(32).hex(),\n'
            changed += 1
    if changed:
        open(path, "w", encoding="utf-8").write("".join(lines))
    return changed


# ---------- 3. tests + exploit -----------------------------------------------
def run_tests(root):
    env = dict(os.environ, **TEST_ENV, PYTHONPATH=root)
    try:
        import pytest  # noqa: F401
        cmd = [sys.executable, "-m", "pytest", "-q", "tests"]
    except ImportError:
        cmd = [sys.executable, "-m", "unittest", "tests.test_app_unittest"]
    r = subprocess.run(cmd, cwd=root, env=env, capture_output=True, text=True)
    tail = (r.stdout + r.stderr).strip().splitlines()[-3:]
    return r.returncode == 0, "\n      ".join(tail)


def exploit(root):
    """UNION injection: try to dump usernames + passwords through the search box."""
    code = (
        "import tempfile, os\n"
        "from vitalcare import create_app\n"
        "fd, p = tempfile.mkstemp()\n"
        "app = create_app({'TESTING': True, 'DATABASE': p})\n"
        "c = app.test_client()\n"
        "c.post('/login', data={'username': 'mira', 'password': 'demo-only'})\n"
        "payload = \"zzz%' UNION SELECT id, username, password_demo, role FROM users --\"\n"
        "r = c.get('/patients/search', query_string={'q': payload})\n"
        "print('LEAKED' if b'demo-only' in r.data else 'SAFE')\n"
    )
    env = dict(os.environ, **TEST_ENV, PYTHONPATH=root)
    r = subprocess.run([sys.executable, "-c", code], cwd=root, env=env, capture_output=True, text=True)
    return r.stdout.strip() or r.stderr.strip()[-200:]


# ---------- main -------------------------------------------------------------
def main():
    root = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else ".")
    print(f"Target: {root}\n")

    print("[1] Baseline tests (before any change)")
    ok, out = run_tests(root)
    print("    ", "PASS" if ok else "FAIL", "\n     ", out)
    if not ok:
        sys.exit("Tests already failing - stopping so we don't blame our patch.")

    print("\n[2] Locating vulnerabilities")
    findings = locate(root)
    for kind, path, n, line in findings:
        print(f"     {kind:17} {os.path.relpath(path, root)}:{n}   {line[:70]}")

    print("\n[3] Exploit BEFORE patch  ->", exploit(root))

    print("\n[4] Patching (backups saved as .bak)")
    for path in py_files(root):
        shutil.copy(path, path + ".bak")
    fixed_sql = sum(patch_sqli(p) for p in py_files(root))
    fixed_sec = sum(patch_secrets(p) for p in py_files(root))
    print(f"     SQL injection fixes: {fixed_sql}   secrets moved to env: {fixed_sec}")

    print("\n[5] Re-check after patch")
    print("     Exploit AFTER patch ->", exploit(root))
    ok, out = run_tests(root)
    print("     Tests:", "PASS (fix did not break the suite)" if ok else "FAIL", "\n     ", out)
    print("\nRemaining secrets in code:", [f for f in locate(root) if f[0] == "Hardcoded secret"] or "none")


if __name__ == "__main__":
    main()
