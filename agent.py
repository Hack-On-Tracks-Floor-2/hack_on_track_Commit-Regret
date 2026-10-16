import argparse
import shutil
import sys
import tempfile
from pathlib import Path
from fixloop import klass
from review import review_site
from detectors import detect

from tools import prepare_repo, discover_sites, setup_env, run_tests
from scanner import scan_site
from fixloop import fix_site, write_report


def as_dict(f):
    if isinstance(f, dict):
        return f
    if hasattr(f, "__dict__"):
        return dict(vars(f))
    return {"explanation": str(f)}

def cls_of(f):
    return klass(f.get("vuln_class") or f.get("class") or f.get("type"))


def to_int(x):
    try:
        return int(x)
    except Exception:
        return 0


def is_dup(a, b):
    return (cls_of(a) == cls_of(b)
            and Path(str(a.get("file", ""))).name == Path(str(b.get("file", ""))).name
            and abs(to_int(a.get("line")) - to_int(b.get("line"))) <= 3)


def get_findings(site):
    # Step 1: candidates from the built-in scanner
    candidates = [as_dict(f) for f in scan_site(site)]

    # Step 2: candidates from Semgrep, Bandit, detect-secrets and webscan
    try:
        tool_found, status = detect(site)
        for tool, s in status.items():
            print(f"   [detect:{tool}] {s}", flush=True)
    except Exception as e:
        print(f"[agent] detectors failed ({str(e)[:80]}); using scanner only", flush=True)
        tool_found = []
    for t in tool_found:
        if t.get("type") == "OTHER":
            continue
        if not any(is_dup(c, t) for c in candidates):
            candidates.append(t)

    # Step 3: LLM triage (drops false positives, adds missed bugs)
    try:
        kept, new, dropped = review_site(site, candidates)
    except Exception as e:
        print(f"[agent] LLM review failed ({str(e)[:80]}); using tool findings only", flush=True)
        return candidates
    for f, why in dropped:
        print(f"   (dropped false positive: {cls_of(f)} {f.get('file')}:{f.get('line')} - {why[:80]})")
    merged = list(kept)
    for n in new:
        if not any(is_dup(m, n) for m in merged):
            merged.append(n)
    return merged


def sweep_old_temp():
    """Delete leftovers from earlier runs (venv_* and agent_* in the temp folder)."""
    tmp = Path(tempfile.gettempdir())
    for pattern in ("venv_*", "agent_*"):
        for p in tmp.glob(pattern):
            shutil.rmtree(p, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser(description="Find and fix vulnerabilities in a repo")
    ap.add_argument("--repo", required=True, help="Local path or git URL")
    ap.add_argument("--fix", action="store_true", help="Patch what is found")
    ap.add_argument("--report", default="report.md")
    args = ap.parse_args()

    sweep_old_temp()

    print(f"[agent] Preparing repo: {args.repo}", flush=True)
    work = prepare_repo(args.repo)
    results = []

    try:
        sites = discover_sites(work)
        if not sites:
            print("[agent] No sites found (no requirements.txt).")
            return 1
        print(f"[agent] Found {len(sites)} site(s): {', '.join(s.name for s in sites)}", flush=True)

        for site in sites:
            print(f"\n[agent] === {site.name} ===", flush=True)
            venv = None
            try:
                try:
                    py = setup_env(site)
                    venv = Path(py).parent.parent
                except RuntimeError as e:
                    print(f"[agent] FAIL: {e}")
                    continue

                ok, summary, out = run_tests(site, py)
                print(f"[agent] baseline: {'PASS' if ok else 'FAIL'} ({summary})", flush=True)
                if not ok:
                    print(out[-800:])
                    continue

                findings = get_findings(site)
                print(f"[agent] {len(findings)} finding(s)", flush=True)
                for f in findings:
                    print(f"   - {f.get('vuln_class') or f.get('class') or f.get('type')} "
                          f"{f.get('file')}:{f.get('line')}")

                if args.fix and findings:
                    results += fix_site(site, py, findings)
            finally:
                if venv:
                    shutil.rmtree(venv, ignore_errors=True)

        if results:
            write_report(results, args.report)
            fixed = sum(1 for r in results if r["status"] == "FIXED")
            print(f"\n[agent] {fixed}/{len(results)} finding(s) fixed. Report: {args.report}")
        return 0
    finally:
        shutil.rmtree(work.parent, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())