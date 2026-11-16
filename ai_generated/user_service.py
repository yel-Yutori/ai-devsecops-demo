import hashlib
import sqlite3
import subprocess

from flask import Flask

# 假的密碼，僅供示範，請勿放入任何真實密碼
DB_PASSWORD = "fake-password-123"


def find_user(name):
    conn = sqlite3.connect("app.db")
    query = f"SELECT * FROM users WHERE name = '{name}'"
    return conn.execute(query).fetchall()


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


def ping_host(host):
    return subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True)


def run_debug_server():
    app = Flask(__name__)
    app.run(debug=True)
