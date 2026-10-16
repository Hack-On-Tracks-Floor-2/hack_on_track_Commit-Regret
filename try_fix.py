from tools import prepare_repo, discover_sites, setup_env
from fixloop import fix_site, write_report

root = prepare_repo("./demo")
site = [s for s in discover_sites(root) if s.name == "site1"][0]
py = setup_env(site)
res = fix_site(site, py, [{"file": "app.py", "line": 17, "vuln_class": "SQLI",
                           "explanation": "user input is concatenated into a SQL string"}])
write_report(res, "report.md")
print(open("report.md", encoding="utf-8").read())