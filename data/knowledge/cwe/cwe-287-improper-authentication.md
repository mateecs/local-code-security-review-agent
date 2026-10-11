# CWE-287: Improper Authentication

## Description
When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

This is a broad class that covers missing, weak, or bypassable authentication.

## Common Manifestations
- Missing authentication on critical functions (CWE-306)
- Authentication bypass via parameter manipulation
- Weak password requirements or storage
- Session fixation or predictable session IDs
- Trusting client-side authentication decisions
- Improper handling of multi-factor authentication
- Authentication logic that fails open

## Impact
- Unauthorized access to accounts and sensitive functionality
- Account takeover
- Privilege escalation
- Full system compromise

## How to Detect in Code
Look for:
- Sensitive endpoints or functions with no authentication decorator/middleware
- Authentication decisions made only on the client
- Custom authentication logic that is incomplete
- Session tokens that are never invalidated
- Password comparison using `==` instead of constant-time comparison

## Prevention
- Require authentication for every non-public resource
- Use well-tested authentication libraries and protocols (OAuth 2.0 / OIDC, SAML, etc.)
- Enforce authentication on the server side only
- Implement proper session management (secure cookies, invalidation on logout, short lifetimes)
- Use multi-factor authentication for sensitive accounts
- Fail securely – deny access when authentication state is unclear

## Related OWASP / CWEs
A07:2021 – Identification and Authentication Failures, CWE-306 (Missing Authentication for Critical Function), CWE-384 (Session Fixation), CWE-798 (Hard-coded Credentials)

## Example Vulnerable Pattern
```python
# Missing authentication on admin function
@app.route("/admin/delete_user")
def delete_user():
    user_id = request.args.get("id")
    db.delete_user(user_id)
    return "Deleted"
```

## Secure Pattern
```python
@app.route("/admin/delete_user")
@login_required
@admin_required
def delete_user():
    user_id = request.args.get("id")
    # additional ownership / authorization checks
    db.delete_user(user_id)
    return "Deleted"
```
