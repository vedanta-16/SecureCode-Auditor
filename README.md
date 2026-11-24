# SecureCode Auditor

A local educational project demonstrating secure coding review through two Flask applications:

- `vulnerable_app/`: intentionally insecure application for a controlled localhost lab.
- `secure_app/`: remediated application using safer coding practices.
- `reports/`: review template and sample findings.
- `tests/`: automated tests for the secured application.
- `scripts/`: helper commands for setup and static analysis.

## Safety

Run only on your own machine at `127.0.0.1`. The vulnerable application deliberately contains security weaknesses. Never expose it to a public network, deploy it, or use it with real credentials or personal data. Use synthetic accounts only.

## Requirements

- Python 3.10+
- Linux, macOS, or Windows
- Internet access for initial package installation

## Setup

```bash
cd SecureCode-Auditor
python3 -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
```

Generate a secret and put it in `.env`:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

Edit `.env` and replace `change-me-use-a-random-secret` with the generated value.
For local HTTP testing, `COOKIE_SECURE=false` is expected. Set it to `true` behind HTTPS in production.

## Run the vulnerable lab

```bash
python vulnerable_app/app.py
```

Open http://127.0.0.1:5001

Demo-only credentials: create your own synthetic account. Passwords are stored in plaintext in this lab database. Do not reuse a real password.

## Run the secured application

In another terminal (or stop the first app):

```bash
python secure_app/app.py
```

Open http://127.0.0.1:5000

Register with a synthetic username and a unique password of at least 12 characters.

## Inspect Stored Password Hashes (Secured Application)

The secured application uses Werkzeug's password-hashing utilities. It stores a salted password hash in the `password_hash` column rather than storing the original password.

### 1. Create a test account

1. Start the secured application:

   ```bash
   python secure_app/app.py
   ```

2. Open <http://127.0.0.1:5000>.
3. Register a synthetic test account using a unique lab-only password.
4. Keep the application running while you inspect the database in a second terminal.

### 2. Open the SQLite database

From the project root directory, run:

```bash
sqlite3 secure_app/users.db
```

At the SQLite prompt, execute:

```sql
SELECT id, username, password_hash FROM users;
```

The output should contain the test account and its stored password hash. The exact hash value will differ for each registration because password hashing uses a salt.

To leave the SQLite prompt, run:

```sql
.quit
```

### 3. Verify a password against its hash

The hash is not decrypted or converted back into the original password. The application verifies a login attempt with Werkzeug's `check_password_hash()` function. It returns `True` when the supplied password matches the stored hash and `False` otherwise.

For a standalone demonstration, run this from the project root while the virtual environment is active:

```bash
python - <<'PY'
from werkzeug.security import generate_password_hash, check_password_hash

test_password = "Example-Lab-Password-123!"
stored_hash = generate_password_hash(test_password)

print("Stored hash:", stored_hash)
print("Correct password:", check_password_hash(stored_hash, test_password))
print("Incorrect password:", check_password_hash(stored_hash, "Not-The-Password"))
PY
```

Expected verification results:

```text
Correct password: True
Incorrect password: False
```

The displayed hash is generated for this demonstration; it is not the hash stored for your registered account.

**Troubleshooting:** If the `sqlite3` command is unavailable, install the SQLite command-line utility for your operating system. On Kali/Debian-based systems, use `sudo apt install sqlite3`.

**Security note:** Use synthetic accounts and lab-only passwords. Never share database dumps or publish password hashes from real users. The vulnerable application intentionally stores plaintext passwords for comparison; do not use real credentials there.

## Run tests

```bash
pytest -q
```

The tests use Flask's test client and a temporary SQLite database. They do not require either server to be running.

## Static analysis

```bash
bandit -r vulnerable_app secure_app
semgrep scan --config p/python secure_app
pip-audit
```

The vulnerable app may produce findings by design. Review every result manually; scanners can produce false positives and cannot prove that code is secure.

## Suggested review workflow

1. Read `reports/security_review_template.md`.
2. Run the scanners and save their output under `reports/`.
3. Inspect the vulnerable app manually.
4. Compare each weakness with the corresponding secure implementation.
5. Run tests and manually verify authorization, login, CSRF, and password hashing.
6. Update the report with actual evidence from your own scans and tests.

## Limitations

This is a learning demonstration, not a production-ready authentication system. A production deployment also needs HTTPS, rate limiting, secure password-reset flows, monitoring, backups, security headers, dependency maintenance, deployment hardening, and a threat model.
