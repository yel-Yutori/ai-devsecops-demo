from app import app


def test_home_page():
    client = app.test_client()
    response = client.get("/")
    assert response.status_code == 200
    assert "DevSecOps" in response.get_data(as_text=True)


def test_security_headers():
    client = app.test_client()
    response = client.get("/")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert "default-src 'self'" in response.headers["Content-Security-Policy"]


def test_health():
    client = app.test_client()
    response = client.get("/health")
    assert response.status_code == 200
    assert response.get_json()["status"] == "ok"
