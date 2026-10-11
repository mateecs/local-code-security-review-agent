"""Cake-shop backend, written defensively. Used to measure false positives."""
import hashlib
import ipaddress
import json
import os
import sqlite3
import subprocess
from functools import wraps
from urllib.parse import urlparse

import requests
from flask import Flask, abort, request, send_from_directory, session
from markupsafe import escape
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.environ["FLASK_SECRET_KEY"]
STRIPE_API_KEY = os.environ.get("STRIPE_API_KEY")
DB_PATH = os.environ.get("DB_PATH", "shop.db")
UPLOAD_DIR = "/var/app/uploads"
ALLOWED_HOSTS = {"api.example.org"}


def get_db():
    return sqlite3.connect(DB_PATH)


def admin_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not session.get("is_admin"):
            abort(403)
        return view(*args, **kwargs)
    return wrapper


def hash_password(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000).hex()


@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]
    db = get_db()
    row = db.execute("SELECT id, salt, pw FROM users WHERE name = ?", (username,)).fetchone()
    if row and hash_password(password, bytes.fromhex(row[1])) == row[2]:
        session["user_id"] = row[0]
        return "ok"
    return "denied", 401


@app.route("/search")
def search():
    term = request.args.get("q", "")
    db = get_db()
    rows = db.execute("SELECT name, price FROM cakes WHERE name LIKE ?", (f"%{term}%",)).fetchall()
    return {"results": rows}


@app.route("/hello")
def hello():
    name = request.args.get("name", "guest")
    return f"<h1>Hello {escape(name)}</h1>"


@app.route("/download")
def download():
    filename = secure_filename(request.args.get("file", ""))
    return send_from_directory(UPLOAD_DIR, filename)


@app.route("/ping")
def ping():
    host = str(ipaddress.ip_address(request.args.get("host", "127.0.0.1")))
    return subprocess.check_output(["ping", "-c", "1", host], timeout=5)


@app.route("/admin/users")
@admin_required
def list_users():
    db = get_db()
    return {"users": db.execute("SELECT id, name, email FROM users").fetchall()}


@app.route("/admin/delete_user", methods=["POST"])
@admin_required
def delete_user():
    db = get_db()
    db.execute("DELETE FROM users WHERE id = ?", (request.form["id"],))
    db.commit()
    return "deleted"


@app.route("/import", methods=["POST"])
@admin_required
def import_session():
    return json.loads(request.get_data())


@app.route("/fetch")
def fetch():
    url = request.args.get("url", "")
    if urlparse(url).hostname not in ALLOWED_HOSTS:
        abort(400)
    return requests.get(url, timeout=5).text


if __name__ == "__main__":
    app.run(host="127.0.0.1", debug=False)
