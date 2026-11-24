# Example Findings — Training Scenarios

These are expected weaknesses intentionally present in `vulnerable_app/app.py`.
They are not scan results and should not be represented as independently verified findings until you inspect the code and reproduce them in your own local lab.

| ID | Finding | Suggested severity | Secure implementation |
|---|---|---|---|
| LAB-01 | SQL injection in login query | High | Parameterized query with placeholders |
| LAB-02 | Plaintext password storage | High | Werkzeug password hashing and verification |
| LAB-03 | Stored XSS in profile bio | High | Jinja autoescaping; never mark untrusted content safe |
| LAB-04 | Hardcoded Flask secret | High | Strong secret from protected environment configuration |
| LAB-05 | Missing CSRF protection | Medium | CSRF tokens on state-changing browser forms |
| LAB-06 | Logout changes state via GET | Low/Medium | POST logout protected by CSRF |
| LAB-07 | Missing object-level authorization | High | Verify the current user owns the requested profile |

Severity is context-dependent. Confirm exploitability, impact, and exposure before assigning a final rating.
