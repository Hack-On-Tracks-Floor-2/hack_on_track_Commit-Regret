import sqlite3
from flask import Flask, request, jsonify, render_template_string, abort

app = Flask(__name__)

DB = sqlite3.connect(":memory:", check_same_thread=False)
DB.execute("create table notes(id integer primary key autoincrement, owner text, title text, body text)")
DB.executemany("insert into notes(owner, title, body) values(?,?,?)",
               [("alice", "groceries", "milk, eggs"),
                ("bob", "private", "bank pin is 4321")])

PAGE = "<h1>{{ title }}</h1><div class='body'>{{ body|safe }}</div>"

def current_user():
    return request.headers.get("X-User", "")

@app.route("/notes", methods=["POST"])
def create_note():
    user = current_user()
    if not user:
        abort(401)
    data = request.get_json()
    cur = DB.execute("insert into notes(owner, title, body) values(?,?,?)",
                     (user, data["title"], data["body"]))
    DB.commit()
    return jsonify(id=cur.lastrowid), 201

@app.route("/notes")
def list_notes():
    user = current_user()
    if not user:
        abort(401)
    rows = DB.execute("select id, title from notes where owner = ?", (user,)).fetchall()
    return jsonify(rows)

@app.route("/notes/<int:note_id>")
def view_note(note_id):
    if not current_user():
        abort(401)
    row = DB.execute("select title, body from notes where id = ?", (note_id,)).fetchone()
    if not row:
        abort(404)
    return render_template_string(PAGE, title=row[0], body=row[1])