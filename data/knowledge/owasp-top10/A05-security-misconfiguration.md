# A05:2021 – Security Misconfiguration

## Overview
Security Misconfiguration is extremely common. It covers missing hardening, unnecessary features enabled, default accounts, overly informative error messages, and insecure cloud/storage permissions.

## Common Issues
- Debug mode left enabled in production (DEBUG=True)
- Default accounts and passwords still active
- Unnecessary features, ports, services, or pages enabled
- Missing security headers (CSP, HSTS, X-Frame-Options, etc.)
- Directory listing enabled
- Overly verbose error messages that leak stack traces, paths, or secrets
- Insecure default configurations in frameworks, servers, or cloud services
- Unprotected sensitive files (.env, .git, backups, config files) served by the web server
- Misconfigured CORS, cloud storage (public buckets), or container permissions

## How to Detect in Code / Config
Look for:
- `DEBUG = True` or equivalent in production settings
- Hardcoded default credentials
- Missing security middleware or headers
- Catch-all exception handlers that print full traceback to users
- Configuration files committed to source control containing secrets
- Open cloud storage or overly permissive IAM roles

## Prevention
- Harden all parts of the stack (server, framework, database, cloud)
- Remove or disable unused features and default accounts
- Use secure configuration templates and automated checks
- Implement a centralized error handling that returns generic messages to users
- Keep software and dependencies up to date
- Automate verification of configuration (IaC scanning, CIS benchmarks)
- Never serve .env, .git, or backup files from the web root
- Apply principle of least privilege everywhere

## Related Topics
Often overlaps with A02 (Cryptographic Failures) when secrets are exposed via misconfiguration, and A06 (Vulnerable Components).

## Example Vulnerable Patterns
```python
# Django / Flask style
DEBUG = True          # never in production
SECRET_KEY = "insecure"

# Verbose errors
@app.errorhandler(Exception)
def handle_error(e):
    return str(e), 500   # leaks internal details
```

## Secure Patterns
```python
DEBUG = False
SECRET_KEY = os.environ["SECRET_KEY"]

@app.errorhandler(Exception)
def handle_error(e):
    logger.exception("Unhandled error")
    return "Internal server error", 500
```
