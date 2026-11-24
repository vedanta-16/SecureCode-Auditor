"""
INTENTIONALLY VULNERABLE training application.
Run ONLY on localhost with synthetic data. Never deploy.
"""
import os
import sqlite3
from flask import Flask, request, redirect, session, render_template_string

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "lab_users.db")

app = Flask(__name__)
app.secret_key = "weak-hardcoded-demo-secret"  # VULN: hardcoded weak secret


def db_connection():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_db():
    with db_connection() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                bio TEXT DEFAULT ''
            )
        """)
        db.commit()


@app.route("/")
def home():
    return """
    <h1>Vulnerable Coding Lab</h1>
    <p>LOCAL TRAINING ONLY — never deploy this application.</p>
    <a href='/register'>Register</a> |
    <a href='/login'>Login</a>
    """


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        try:
            with db_connection() as db:
                # VULN: password stored in plaintext.
                db.execute(
                    "INSERT INTO users (username, password) VALUES (?, ?)",
                    (username, password)
                )
                db.commit()
        except sqlite3.IntegrityError:
            return "Username already exists", 409
        return redirect("/login")

    return """
    <h2>Register (intentionally insecure)</h2>
    <form method='post'>
      <input name='username' placeholder='Username' required>
      <input name='password' type='password' placeholder='Password' required>
      <button>Register</button>
    </form>
    """


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        with db_connection() as db:
            # VULN: SQL injection via string concatenation.
            query = (
                "SELECT * FROM users WHERE username = '" + username +
                "' AND password = '" + password + "'"
            )
            user = db.execute(query).fetchone()

        if user:
            # VULN: session fixation protection is absent; weak secret is above.
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect("/profile")
        return "Invalid credentials", 401

    return """
    <h2>Login (intentionally insecure)</h2>
    <form method='post'>
      <input name='username' placeholder='Username' required>
      <input name='password' type='password' placeholder='Password' required>
      <button>Login</button>
    </form>
    """


@app.route("/profile", methods=["GET", "POST"])
def profile():
    if "user_id" not in session:
        return redirect("/login")

    if request.method == "POST":
        bio = request.form.get("bio", "")
        with db_connection() as db:
            db.execute("UPDATE users SET bio = ? WHERE id = ?", (bio, session["user_id"]))
            db.commit()

    with db_connection() as db:
        user = db.execute(
            "SELECT username, bio FROM users WHERE id = ?",
            (session["user_id"],)
        ).fetchone()

    # VULN: untrusted bio inserted into HTML without escaping (stored XSS).
    return render_template_string("""
      <h2>Profile for {{ username }}</h2>
      <p>Bio: """ + (user["bio"] or "") + """</p>
      <form method='post'>
        <textarea name='bio' placeholder='Your bio'></textarea>
        <button>Save bio</button>
      </form>
      <a href='/logout'>Logout</a>
    """, username=user["username"])


@app.route("/logout")
def logout():
    # VULN: state-changing logout uses GET and no CSRF protection.
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    init_db()
    # Bound to loopback intentionally; do not change to 0.0.0.0.
    app.run(host="127.0.0.1", port=5001, debug=False)
