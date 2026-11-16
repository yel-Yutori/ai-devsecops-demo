from pathlib import Path

from app import app

app.config["SCAN_MIN_INTERVAL"] = 0

SAMPLES = Path(__file__).parent / "static" / "samples"
VULNERABLE = (SAMPLES / "vulnerable.txt").read_text(encoding="utf-8")
SAFE = (SAMPLES / "safe.txt").read_text(encoding="utf-8")


def post(code):
    return app.test_client().post("/api/scan", json={"code": code})


def test_home_page():
    response = app.test_client().get("/")
    assert response.status_code == 200
    assert "程式碼安檢站" in response.get_data(as_text=True)


def test_health():
    response = app.test_client().get("/health")
    assert response.get_json()["status"] == "ok"


def test_security_headers():
    response = app.test_client().get("/")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert "default-src 'self'" in response.headers["Content-Security-Policy"]


def test_vulnerable_code_is_rejected():
    data = post(VULNERABLE).get_json()
    assert data["passed"] is False
    assert data["blocking"] >= 2


def test_safe_code_passes():
    data = post(SAFE).get_json()
    assert data["passed"] is True


def test_nosec_comment_cannot_bypass_scan():
    code = "import subprocess\nsubprocess.run(f'ls {user_input}', shell=True)  # nosec\n"
    assert post(code).get_json()["passed"] is False


def test_syntax_error_is_rejected():
    data = post("def broken(:\n").get_json()
    assert data["passed"] is False
    assert data["stages"][0]["status"] == "fail"


def test_oversized_code_is_refused():
    assert post("x = 1\n" * 2000).status_code == 413


def test_bad_requests_are_refused():
    client = app.test_client()
    assert client.post("/api/scan", data="x").status_code == 415
    assert client.post("/api/scan", json={"nope": 1}).status_code == 400
    assert post("   ").status_code == 400
