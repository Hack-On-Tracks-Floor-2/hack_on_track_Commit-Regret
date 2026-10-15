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
    run([str(py), "-m", "pip", "install", "-q", "-r", "requirements.txt", "pytest"],
        cwd=site, timeout=400)
    return str(py)

def run_tests(site, py):
    code, out = run([py, "-m", "pytest", "-q"], cwd=site)
    lines = [l for l in out.strip().splitlines() if l.strip()]
    return code == 0, (lines[-1] if lines else "no output"), out