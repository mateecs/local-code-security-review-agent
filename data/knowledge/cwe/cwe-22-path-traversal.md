# CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

## Description
The software uses external input to construct a pathname that is intended to be within a restricted directory, but it does not properly neutralize special elements such as ".." that can resolve to a location outside that directory.

Also known as directory traversal or path injection.

## Impact
- Reading arbitrary files from the server (source code, configuration, /etc/passwd, private keys)
- Writing or overwriting files outside the intended directory
- In some cases, remote code execution

## How to Detect in Code
Look for:
- User-controlled input used in `open()`, `send_file()`, file download/upload paths, or include/require statements
- Missing canonicalization or base-directory checks
- Use of `../` sequences that are not stripped or rejected

## Prevention
- Prefer using identifiers (IDs) instead of raw filenames supplied by users
- Canonicalize the path and verify it starts with the expected base directory
- Use allow-lists for permitted filenames or extensions
- Avoid passing user input directly into file system APIs
- Run the application with least privilege so even successful traversal has limited impact

## Related OWASP
A01:2021 – Broken Access Control, A03:2021 – Injection

## Example Vulnerable Code
```python
# Classic path traversal
filename = request.args.get("file")
with open(f"/var/www/uploads/{filename}", "r") as f:
    return f.read()
# Attacker supplies: ../../../etc/passwd
```

## Secure Code
```python
import os
from pathlib import Path

BASE_DIR = Path("/var/www/uploads").resolve()

filename = request.args.get("file")
# Reject suspicious names early
if ".." in filename or filename.startswith("/"):
    abort(400)

target = (BASE_DIR / filename).resolve()
if not str(target).startswith(str(BASE_DIR)):
    abort(403)

with open(target, "r") as f:
    return f.read()
```
