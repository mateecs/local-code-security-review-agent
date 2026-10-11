# A01:2021 – Broken Access Control

## Overview
Broken Access Control is the #1 risk in OWASP Top 10 2021. 94% of applications tested had some form of broken access control. It has the highest number of occurrences in real-world data.

Access control enforces that users cannot act outside their intended permissions. Failures lead to unauthorized information disclosure, modification, destruction of data, or performing actions outside the user's limits.

## Common Vulnerabilities
- Violation of least privilege or "deny by default"
- Bypassing access checks by modifying URL, parameters, internal state, or HTML
- Insecure Direct Object References (IDOR) – viewing/editing another user's data by changing an ID
- Missing access controls on APIs (especially POST, PUT, DELETE)
- Elevation of privilege (acting as admin while logged in as normal user, or acting without login)
- Metadata manipulation (JWT, cookies, hidden fields)
- CORS misconfiguration allowing unauthorized origins
- Force browsing to authenticated or privileged pages

## How to Detect in Code
Look for:
- Missing authorization checks before sensitive operations
- Direct use of user-controlled IDs in queries without ownership verification
- Client-side only access control (can be bypassed)
- Hardcoded role checks that can be manipulated
- APIs that accept any user ID without verifying the caller owns the resource

## Prevention
- Enforce access control in trusted server-side code only
- Deny by default for all resources except public ones
- Implement access control once and reuse it everywhere
- Enforce record ownership (user can only access their own records)
- Disable directory listing and ensure sensitive files (.git, backups) are not in web roots
- Log access control failures and alert on repeated failures
- Rate-limit API access
- Invalidate session identifiers on logout; keep JWTs short-lived
- Include functional access control tests in unit and integration tests

## Related CWEs
CWE-22 (Path Traversal), CWE-200 (Exposure of Sensitive Information), CWE-284 (Improper Access Control), CWE-285 (Improper Authorization), CWE-352 (CSRF), CWE-639 (Authorization Bypass Through User-Controlled Key), CWE-862 (Missing Authorization), CWE-863 (Incorrect Authorization)

## Example Vulnerable Pattern
```python
# Bad – no ownership check
@app.route("/account/<acct_id>")
def get_account(acct_id):
    return db.query(f"SELECT * FROM accounts WHERE id = {acct_id}")
```

## Secure Pattern
```python
# Good – verify ownership
@app.route("/account/<acct_id>")
@login_required
def get_account(acct_id):
    account = db.get_account(acct_id)
    if account.owner_id != current_user.id:
        abort(403)
    return account
```
