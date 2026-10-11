# A03:2021 – Injection

## Overview
Injection ranked #3 in OWASP Top 10 2021. 94% of applications were tested for some form of injection. Includes SQL, NoSQL, OS command, LDAP, Expression Language, and Cross-site Scripting (XSS is now part of this category).

An application is vulnerable when user-supplied data is not validated, filtered, or sanitized, and is used directly in interpreters or queries.

## Common Types
- SQL Injection (CWE-89)
- Cross-site Scripting / XSS (CWE-79)
- OS Command Injection (CWE-78)
- LDAP Injection
- NoSQL Injection
- Expression Language / OGNL Injection
- Server-Side Template Injection (SSTI)

## How Injection Happens
- Dynamic queries built by concatenating user input
- Non-parameterized calls to interpreters
- Hostile data used in ORM search parameters
- Missing output encoding for HTML/JS contexts

## How to Detect in Code
Look for:
- String concatenation or f-strings used to build SQL/commands
- `eval()`, `exec()`, `os.system()`, `subprocess` with user input
- Template engines rendering untrusted data without auto-escaping
- Direct insertion of request parameters into HTML
- Missing parameterized queries / prepared statements

## Prevention
- Prefer safe APIs that avoid the interpreter entirely (parameterized queries, ORMs)
- Use positive (allow-list) server-side input validation
- Escape special characters with the correct syntax for the interpreter
- Never use user input for SQL structure (table/column names)
- Context-aware output encoding for XSS prevention
- Keep data and commands strictly separated

## Related CWEs
CWE-20 (Improper Input Validation), CWE-74 (Injection), CWE-77 (Command Injection), CWE-78 (OS Command Injection), CWE-79 (XSS), CWE-89 (SQL Injection), CWE-94 (Code Injection)

## Example Vulnerable Patterns
```python
# SQL Injection
query = f"SELECT * FROM users WHERE id = '{user_id}'"
cursor.execute(query)

# Command Injection
os.system(f"ping {user_input}")

# XSS
return f"<h1>Hello {username}</h1>"
```

## Secure Patterns
```python
# Parameterized query
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

# Safe subprocess
subprocess.run(["ping", "-c", "1", user_input], check=True)  # still validate input

# Output encoding (use framework auto-escape or markupsafe)
from markupsafe import escape
return f"<h1>Hello {escape(username)}</h1>"
```
