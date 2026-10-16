import argparse
import shutil
import sys
import tempfile
from pathlib import Path
from fixloop import klass
from review import review_site

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


def get_findings(site):
    scanned = [as_dict(f) for f in scan_site(site)]
    try:
        kept, new, dropped = review_site(site, scanned)
    except Exception as e:
        print(f"[agent] LLM review failed ({str(e)[:80]}); using scanner findings only", flush=True)
        return scanned
    for f, why in dropped:
        print(f"   (dropped false positive: {cls_of(f)} {f.get('file')}:{f.get('line')} - {why[:80]})")
    merged = list(kept)
    for n in new:
        dup = any(cls_of(m) == cls_of(n)
                  and Path(str(m.get("file", ""))).name == Path(str(n.get("file", ""))).name
                  and abs(to_int(m.get("line")) - to_int(n.get("line"))) <= 3
                  for m in merged)
        if not dup:
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