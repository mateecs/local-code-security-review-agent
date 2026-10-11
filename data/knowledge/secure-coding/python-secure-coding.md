# Python Secure Coding Practices (Security-Focused)

## Input Validation & Injection Prevention
- Never trust user input. Validate on the server side.
- Prefer allow-lists over deny-lists.
- Use parameterized queries for all database access.
- Avoid `eval()`, `exec()`, `os.system()`, and `shell=True` with user input.
- Use `subprocess.run([...], shell=False)` and pass arguments as a list.

## Output Encoding & XSS
- Always encode untrusted data for the output context (HTML, JS, URL, CSS).
- Prefer frameworks that auto-escape templates (Jinja2 with autoescape, Django templates).
- Use `markupsafe.escape` when manually building HTML.

## Authentication & Session Management
- Use established libraries (Flask-Login, Django auth, Authlib, etc.).
- Store password hashes with bcrypt, Argon2, or scrypt (never MD5/SHA-1).
- Set secure cookie flags: `HttpOnly`, `Secure`, `SameSite=Lax` or `Strict`.
- Invalidate sessions on logout and privilege changes.
- Protect against session fixation.

## Secrets Management
- Never hard-code secrets, API keys, or passwords.
- Load secrets from environment variables or a secret manager.
- Keep `.env` files out of version control (add to `.gitignore`).
- Rotate secrets regularly.

## Cryptography
- Use the `cryptography` library or well-maintained high-level APIs.
- Prefer authenticated encryption (AES-GCM, ChaCha20-Poly1305).
- Never invent your own crypto.
- Use TLS 1.2+ for all network communication.

## Error Handling & Logging
- Do not leak stack traces, internal paths, or sensitive data to users.
- Log security-relevant events (failed logins, access control failures).
- Avoid logging secrets or full request bodies containing credentials.

## File Handling
- Never use user-supplied filenames directly in path operations.
- Canonicalize paths and verify they stay inside an allowed base directory.
- Restrict uploaded file types and sizes; store outside the web root when possible.

## Dependencies
- Keep dependencies up to date.
- Use tools such as `pip-audit`, `safety`, or GitHub Dependabot.
- Pin versions and prefer packages with good security track records.

## Common Dangerous Patterns to Flag
```python
# Dangerous
eval(user_input)
exec(user_input)
os.system(f"cmd {user_input}")
subprocess.call(user_input, shell=True)
query = f"SELECT * FROM t WHERE id = '{user_id}'"
open(f"/uploads/{filename}")
hashlib.md5(password.encode())
SECRET = "hardcoded-secret"
DEBUG = True  # in production
```
