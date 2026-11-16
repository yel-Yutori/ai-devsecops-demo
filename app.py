import os
import threading
import time

from flask import Flask, jsonify, render_template, request

from scanner import MAX_CODE_CHARS, scan_code

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024
app.config["SCAN_MIN_INTERVAL"] = 1.0

VERSION = os.environ.get("APP_VERSION", "dev")[:7]

_lock = threading.Lock()
_last_scan = 0.0


def too_fast():
    global _last_scan
    now = time.monotonic()
    with _lock:
        if now - _last_scan < app.config["SCAN_MIN_INTERVAL"]:
            return True
        _last_scan = now
        return False


@app.after_request
def add_security_headers(response):
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


@app.route("/")
def home():
    return render_template("index.html", version=VERSION, max_chars=MAX_CODE_CHARS)


@app.route("/health")
def health():
    return jsonify(status="ok")


@app.route("/api/scan", methods=["POST"])
def api_scan():
    if not request.is_json:
        return jsonify(error="請求格式必須是 JSON"), 415
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not isinstance(data.get("code"), str):
        return jsonify(error="缺少 code 欄位"), 400
    code = data["code"]
    if not code.strip():
        return jsonify(error="請先輸入程式碼"), 400
    if len(code) > MAX_CODE_CHARS:
        return jsonify(error=f"程式碼不可超過 {MAX_CODE_CHARS} 字"), 413
    if too_fast():
        return jsonify(error="送出太頻繁，請稍等一秒"), 429
    return jsonify(scan_code(code))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
