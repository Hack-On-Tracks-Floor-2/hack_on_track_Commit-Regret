"""Security tests for site1. They FAIL while the bug exists and PASS once it is fixed."""
import re
from pathlib import Path

from app import app

LEAKED_TOKEN = "internal-9f8e7d6c5b4a3210fedcba"
SITE_DIR = Path(__file__).resolve().parent.parent


def test_sqli_employees_dept_is_not_injectable():
    # A real department filter must never turn into "return every row".
    r = app.test_client().get("/employees", query_string={"dept": "' OR '1'='1"})
    assert r.json == [], "SQL injection: injected condition returned rows"


def test_sqli_union_cannot_read_other_tables():
    payload = "x' UNION SELECT 1, name, 'leak' FROM sqlite_master --"
    r = app.test_client().get("/employees", query_string={"dept": payload})
    assert r.status_code in (200, 400) and "leak" not in r.get_data(as_text=True)


def test_secret_is_not_hardcoded_in_config():
    src = (SITE_DIR / "config.py").read_text(encoding="utf-8")
    assert not re.search(r"""ADMIN_TOKEN\s*=\s*["'][^"']+["']""", src), \
        "ADMIN_TOKEN is a literal in config.py (read it from the environment)"


def test_leaked_token_no_longer_grants_access():
    r = app.test_client().get("/stats", headers={"X-API-Key": LEAKED_TOKEN})
    assert r.status_code == 401, "the token committed to source still works"
