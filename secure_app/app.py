"""Remediated Flask training application."""
import os
import sqlite3
from functools import wraps
from pathlib import Path

from dotenv import load_dotenv
from flask import (
    Flask, abort, g, redirect, render_template_string,
    request, session, url_for
)
from flask_wtf.csrf import CSRFProtect, generate_csrf
from werkzeug.security import check_password_hash, generate_password_hash

PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")

DATABASE = Path(__file__).resolve().parent / "users.db"


def create_app(test_config=None):
    app = Flask(__name__)
    secret = os.getenv("SECRET_KEY")
    if not secret and not test_config:
        raise RuntimeError("Set SECRET_KEY in the project .env file.")
    app.config.update(
        SECRET_KEY=secret or "test-only-secret-not-for-deployment",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.getenv("COOKIE_SECURE", "false").lower() == "true",
        MAX_CONTENT_LENGTH=16 * 1024,
    )
    if test_config:
        app.config.update(test_config)

    CSRFProtect(app)

    def get_db():
        if "db" not in g:
            db_path = app.config.get("DATABASE", str(DATABASE))
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
            g.db = sqlite3.connect(db_path)
            g.db.row_factory = sqlite3.Row
        return g.db

    @app.teardown_appcontext
    def close_db(exception=None):
        db = g.pop("db", None)
        if db is not None:
            db.close()

    def init_db():
        with app.app_context():
            db = get_db()
            db.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    bio TEXT NOT NULL DEFAULT ''
                )
            """)
            db.commit()

    def login_required(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if "user_id" not in session:
                return redirect(url_for("login"))
            return view(*args, **kwargs)
        return wrapped

    @app.after_request
    def security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'"
        )
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.route("/")
    def home():
        return render_template_string("""
          <h1>SecureCode Auditor — secured demo</h1>
          <a href="{{ url_for('register') }}">Register</a> |
          <a href="{{ url_for('login') }}">Login</a>
        """)

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            if not 3 <= len(username) <= 30:
                abort(400, "Username must be 3–30 characters.")
            if not 12 <= len(password) <= 128:
                abort(400, "Password must be 12–128 characters.")

            password_hash = generate_password_hash(password)
            try:
                db = get_db()
                db.execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (username, password_hash),
                )
                db.commit()
            except sqlite3.IntegrityError:
                return "Registration could not be completed.", 409
            return redirect(url_for("login"))

        return render_template_string("""
          <h2>Register</h2>
          <form method="post">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <label>Username <input name="username" minlength="3" maxlength="30" required></label>
            <label>Password <input name="password" type="password" minlength="12" maxlength="128" required></label>
            <button type="submit">Register</button>
          </form>
        """, csrf_token=generate_csrf)

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            user = get_db().execute(
                "SELECT id, username, password_hash FROM users WHERE username = ?",
                (username,),
            ).fetchone()

            if user and check_password_hash(user["password_hash"], password):
                session.clear()
                session["user_id"] = user["id"]
                session["username"] = user["username"]
                return redirect(url_for("profile", user_id=user["id"]))
            return "Invalid username or password.", 401

        return render_template_string("""
          <h2>Login</h2>
          <form method="post">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <label>Username <input name="username" required></label>
            <label>Password <input name="password" type="password" required></label>
            <button type="submit">Login</button>
          </form>
        """, csrf_token=generate_csrf)

    @app.route("/profile/<int:user_id>", methods=["GET", "POST"])
    @login_required
    def profile(user_id):
        if user_id != session["user_id"]:
            abort(403)

        db = get_db()
        if request.method == "POST":
            bio = request.form.get("bio", "")
            if len(bio) > 500:
                abort(400, "Bio must be 500 characters or fewer.")
            db.execute(
                "UPDATE users SET bio = ? WHERE id = ?",
                (bio, user_id),
            )
            db.commit()

        user = db.execute(
            "SELECT id, username, bio FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
        if user is None:
            abort(404)

        # Jinja autoescapes user-controlled values in HTML templates.
        return render_template_string("""
          <h2>Profile for {{ user.username }}</h2>
          <p>Bio: {{ user.bio }}</p>
          <form method="post">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <label>Bio <textarea name="bio" maxlength="500">{{ user.bio }}</textarea></label>
            <button type="submit">Save bio</button>
          </form>
          <form method="post" action="{{ url_for('logout') }}">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <button type="submit">Logout</button>
          </form>
        """, user=user, csrf_token=generate_csrf)

    @app.route("/logout", methods=["POST"])
    @login_required
    def logout():
        session.clear()
        return redirect(url_for("home"))

    with app.app_context():
        init_db()

    return app


if __name__ == "__main__":
    application = create_app()
    # Loopback only for this educational project.
    application.run(host="127.0.0.1", port=5000, debug=False)
