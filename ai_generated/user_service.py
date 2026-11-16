import hashlib
import ipaddress
import os
import sqlite3
import subprocess

from flask import Flask

# 機密從環境變數讀取，不寫在程式裡
DB_PASSWORD = os.environ.get("DB_PASSWORD")


def find_user(name):
    conn = sqlite3.connect("app.db")
    # 使用參數化查詢，輸入不會被當成指令
    return conn.execute(
        "SELECT * FROM users WHERE name = ?", (name,)
    ).fetchall()


def hash_password(password, salt):
    # 使用加鹽且刻意很慢的雜湊，增加暴力破解的成本
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt, 600_000
    ).hex()


def ping_host(host):
    # 先驗證輸入一定是合法 IP，不通過會直接丟出錯誤
    ipaddress.ip_address(host)
    return subprocess.run(
        ["ping", "-c", "1", host], capture_output=True, check=False
    )


def create_app():
    return Flask(__name__)
