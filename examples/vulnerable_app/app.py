"""Cake-shop backend (intentionally vulnerable demo used to evaluate secagent). DO NOT DEPLOY."""
import hashlib
import os
import pickle
import sqlite3
import subprocess

import requests
from flask import Flask, request, render_template_string, send_file

app = Flask(__name__)
app.secret_key = "super-secret-key-123"
DB_PATH = "shop.db"
UPLOAD_DIR = "/var/app/uploads"


def get_db():
    return sqlite3.connect(DB_PATH)


@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]
    pw_hash = hashlib.md5(password.encode()).hexdigest()
    db = get_db()
    query = f"SELECT id FROM users WHERE name = '{username}' AND pw = '{pw_hash}'"
    row = db.execute(query).fetchone()
    return "ok" if row else "denied"


@app.route("/search")
def search():
    term = request.args.get("q", "")
    db = get_db()
    rows = db.execute("SELECT name, price FROM cakes WHERE name LIKE '%" + term + "%'").fetchall()
    return {"results": rows}


@app.route("/hello")
def hello():
    name = request.args.get("name", "guest")
    return render_template_string("<h1>Hello " + name + "</h1>")


@app.route("/download")
def download():
    filename = request.args.get("file")
    return send_file(os.path.join(UPLOAD_DIR, filename))


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    return subprocess.check_output("ping -c 1 " + host, shell=True)


@app.route("/admin/users")
def list_users():
    db = get_db()
    return {"users": db.execute("SELECT id, name, email FROM users").fetchall()}


@app.route("/admin/delete_user", methods=["POST"])
def delete_user():
    user_id = request.form["id"]
    db = get_db()
    db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.commit()
    return "deleted"


@app.route("/import", methods=["POST"])
def import_session():
    return pickle.loads(request.get_data())


@app.route("/fetch")
def fetch():
    url = request.args.get("url")
    return requests.get(url, verify=False).text


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
