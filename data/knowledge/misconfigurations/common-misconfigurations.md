# Common Security Misconfigurations

## Debug Mode Enabled in Production
- `DEBUG = True` (Django/Flask)
- Detailed error pages that reveal stack traces, local variables, file paths, and sometimes secrets
- Fix: Always set DEBUG=False (or equivalent) in production. Use proper logging instead.

## Secrets in Source Code or Config Files
- Hardcoded passwords, API keys, tokens, private keys
- `.env` files committed to Git
- Secrets in Docker images or Kubernetes manifests without encryption
- Fix: Use secret managers, environment variables, and secret scanning in CI.

## Default or Weak Credentials
- Unchanged default admin passwords
- Weak or shared passwords across environments
- Fix: Force password change on first login; use strong unique credentials.

## Missing Security Headers
Important headers to set:
- `Content-Security-Policy`
- `Strict-Transport-Security` (HSTS)
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY` or `SAMEORIGIN`
- `Referrer-Policy`
- `Permissions-Policy`

## Overly Permissive CORS
- `Access-Control-Allow-Origin: *` combined with credentials
- Reflecting the Origin header without validation
- Fix: Explicit allow-list of trusted origins.

## Directory Listing & Sensitive Files Exposed
- Web server allows listing of directories
- `.git`, `.env`, backup files, IDE configs reachable via HTTP
- Fix: Disable directory listing; block sensitive paths at the web server / WAF level.

## Unnecessary Features Enabled
- Admin interfaces, debug endpoints, test pages left accessible
- Unused HTTP methods (TRACE, etc.)
- Fix: Disable or protect everything not required in production.

## Cloud & Infrastructure Misconfigurations
- Public S3 / GCS buckets
- Overly permissive IAM roles / security groups
- Databases exposed to the internet without authentication
- Fix: Follow least privilege, use private networking, enable logging and monitoring.

## Verbose Error Messages
- Returning exception details, SQL errors, or internal paths to the client
- Fix: Generic error messages for users; detailed logs only on the server.
