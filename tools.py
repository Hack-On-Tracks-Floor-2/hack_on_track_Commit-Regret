import os, sys, shutil, subprocess, tempfile
from pathlib import Path

def run(cmd, cwd=None, timeout=180):
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout + p.stderr)
    except subprocess.TimeoutExpired:
        return 124, "timeout"

def prepare_repo(repo):
    work = Path(tempfile.mkdtemp(prefix="agent_")) / "repo"
    if repo.startswith(("http://", "https://", "git@")):
        run(["git", "clone", "--depth", "1", repo, str(work)])
    else:
        shutil.copytree(repo, work)
    if not (work / ".git").exists():
        run(["git", "init"], cwd=work)
        run(["git", "add", "-A"], cwd=work)
        run(["git", "-c", "user.name=agent", "-c", "user.email=a@a",
             "commit", "-m", "baseline"], cwd=work)
    return work

def discover_sites(root):
    return sorted(p.parent for p in Path(root).rglob("requirements.txt")
                  if ".venv" not in p.parts)

def setup_env(site):
    venv = Path(tempfile.mkdtemp(prefix="venv_"))
    run([sys.executable, "-m", "venv", str(venv)])
    py = venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    code, out = run([str(py), "-m", "pip", "install", "-q", "-r", "requirements.txt", "pytest"],
site, timeout=400) 
    if code != 0:
        raise RuntimeError("pip install failed:\n" + out)
    return str(py)

def run_tests(site, py):
    code, out = run([py, "-m", "pytest", "-q"], cwd=site)
    lines = [l for l in out.strip().splitlines() if l.strip()]
    return code == 0, (lines[-1] if lines else "no output"), out

def run_security_tests(site, py, tests_root):
    """Copy security_tests/<site name>/test_security.py into the site and run it.
    Returns (None, msg, out) if there is no security test for this site."""
    src = Path(tests_root) / site.name / "test_security.py"
    if not src.exists():
        return None, "no security tests for this site", ""
    dst_dir = site / "tests"
    dst_dir.mkdir(exist_ok=True)
    shutil.copy(src, dst_dir / "test_security.py")
    code, out = run([py, "-m", "pytest", "-q", "-rf", "tests/test_security.py"], cwd=site)
    failed = [l.split(" - ")[0].replace("FAILED ", "").split("::")[-1]
              for l in out.splitlines() if l.startswith("FAILED")]
    lines = [l for l in out.strip().splitlines() if l.strip()]
    return code == 0, (lines[-1] if lines else "no output"), failed