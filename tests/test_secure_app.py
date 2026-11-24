import sqlite3
from werkzeug.security import check_password_hash
from secure_app.app import create_app


def make_client(tmp_path):
    db_path = tmp_path / "test_users.db"
    app = create_app({
        "TESTING": True,
        "WTF_CSRF_ENABLED": False,  # CSRF is tested separately in real browser/manual testing.
        "DATABASE": str(db_path),
        "SECRET_KEY": "test-secret-key-only",
    })
    return app, app.test_client(), db_path


def register(client, username="alice", password="correct-horse-battery"):
    return client.post("/register", data={
        "username": username,
        "password": password,
    })


def test_register_stores_password_hash(tmp_path):
    app, client, db_path = make_client(tmp_path)
    response = register(client)
    assert response.status_code == 302

    with sqlite3.connect(db_path) as db:
        stored = db.execute(
            "SELECT password_hash FROM users WHERE username = ?",
            ("alice",),
        ).fetchone()[0]

    assert stored != "correct-horse-battery"
    assert check_password_hash(stored, "correct-horse-battery")


def test_login_and_access_own_profile(tmp_path):
    app, client, _ = make_client(tmp_path)
    register(client)
    response = client.post("/login", data={
        "username": "alice",
        "password": "correct-horse-battery",
    })
    assert response.status_code == 302
    profile = client.get("/profile/1")
    assert profile.status_code == 200
    assert b"alice" in profile.data


def test_unauthenticated_profile_redirects(tmp_path):
    app, client, _ = make_client(tmp_path)
    response = client.get("/profile/1")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_user_cannot_access_another_users_profile(tmp_path):
    app, client, _ = make_client(tmp_path)
    register(client, "alice")
    register(client, "bob")
    client.post("/login", data={
        "username": "alice",
        "password": "correct-horse-battery",
    })
    response = client.get("/profile/2")
    assert response.status_code == 403


def test_profile_escapes_html(tmp_path):
    app, client, _ = make_client(tmp_path)
    register(client)
    client.post("/login", data={
        "username": "alice",
        "password": "correct-horse-battery",
    })
    response = client.post("/profile/1", data={"bio": "<script>alert(1)</script>"})
    assert response.status_code == 200
    assert b"&lt;script&gt;" in response.data
    assert b"<script>alert(1)</script>" not in response.data


def test_security_headers_present(tmp_path):
    app, client, _ = make_client(tmp_path)
    response = client.get("/")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "Content-Security-Policy" in response.headers
