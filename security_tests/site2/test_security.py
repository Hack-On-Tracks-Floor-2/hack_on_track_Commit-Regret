"""Security tests for site2. They FAIL while the bug exists and PASS once it is fixed."""
from app import app

XSS = "<script>alert(1)</script>"


def hdr(user):
    return {"X-User": user}


def test_stored_xss_body_is_escaped():
    c = app.test_client()
    nid = c.post("/notes", json={"title": "t", "body": XSS}, headers=hdr("carol")).json["id"]
    html = c.get(f"/notes/{nid}", headers=hdr("carol")).get_data(as_text=True)
    assert XSS not in html, "stored XSS: script tag rendered unescaped"


def test_stored_xss_title_is_escaped():
    c = app.test_client()
    nid = c.post("/notes", json={"title": XSS, "body": "b"}, headers=hdr("carol")).json["id"]
    html = c.get(f"/notes/{nid}", headers=hdr("carol")).get_data(as_text=True)
    assert XSS not in html


def test_idor_other_user_cannot_read_note():
    c = app.test_client()
    nid = c.post("/notes", json={"title": "secret", "body": "pin 9999"},
                 headers=hdr("carol")).json["id"]
    r = c.get(f"/notes/{nid}", headers=hdr("mallory"))
    assert r.status_code in (403, 404), "IDOR: another user read carol's note"
    assert "pin 9999" not in r.get_data(as_text=True)


def test_idor_seeded_private_note_is_protected():
    r = app.test_client().get("/notes/2", headers=hdr("alice"))  # bob's note
    assert r.status_code in (403, 404)


def test_owner_can_still_read_own_note():
    c = app.test_client()
    nid = c.post("/notes", json={"title": "mine", "body": "ok"}, headers=hdr("erin")).json["id"]
    assert c.get(f"/notes/{nid}", headers=hdr("erin")).status_code == 200
