from app import app
from config import ADMIN_TOKEN

def test_filter_by_dept():
    assert len(app.test_client().get("/employees?dept=eng").json) == 2

def test_unknown_dept_empty():
    assert app.test_client().get("/employees?dept=zzz").json == []

def test_stats_requires_token():
    assert app.test_client().get("/stats").status_code == 401

def test_stats_with_token():
    r = app.test_client().get("/stats", headers={"X-API-Key": ADMIN_TOKEN})
    assert r.json == {"count": 3}