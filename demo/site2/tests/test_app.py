from app import app

def hdr(user):
    return {"X-User": user}

def test_requires_login():
    assert app.test_client().get("/notes").status_code == 401

def test_create_and_list():
    c = app.test_client()
    r = c.post("/notes", json={"title": "t1", "body": "hello"}, headers=hdr("carol"))
    assert r.status_code == 201
    titles = [n[1] for n in c.get("/notes", headers=hdr("carol")).json]
    assert "t1" in titles

def test_owner_can_view_own_note():
    r = app.test_client().get("/notes/1", headers=hdr("alice"))
    assert r.status_code == 200 and b"groceries" in r.data

def test_missing_note_404():
    assert app.test_client().get("/notes/999", headers=hdr("alice")).status_code == 404

def test_plain_text_body_renders():
    c = app.test_client()
    nid = c.post("/notes", json={"title": "x", "body": "just text"}, headers=hdr("dave")).json["id"]
    assert b"just text" in c.get(f"/notes/{nid}", headers=hdr("dave")).data