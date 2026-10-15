import sqlite3
from flask import Flask, request, jsonify
from config import ADMIN_TOKEN

app = Flask(__name__)

def get_db():
    c = sqlite3.connect(":memory:")
    c.execute("create table employees(id integer primary key, name text, dept text)")
    c.executemany("insert into employees(name, dept) values(?,?)",
                  [("alice", "eng"), ("bob", "sales"), ("carol", "eng")])
    return c

@app.route("/employees")
def employees():
    dept = request.args.get("dept", "")
    rows = get_db().execute(
        "SELECT id, name, dept FROM employees WHERE dept = '" + dept + "'"
    ).fetchall()
    return jsonify(rows)

@app.route("/stats")
def stats():
    if request.headers.get("X-API-Key") != ADMIN_TOKEN:
        return jsonify(error="unauthorized"), 401
    n = get_db().execute("select count(*) from employees").fetchone()[0]
    return jsonify(count=n)