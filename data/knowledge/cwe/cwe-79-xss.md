# CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

## Description
The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output used as a web page. This allows an attacker to execute scripts in the victim's browser.

XSS is consistently ranked among the top most dangerous software weaknesses (CWE Top 25).

## Types of XSS
- **Reflected XSS**: Malicious script is reflected off the server (e.g., in a search result or error message)
- **Stored XSS**: Malicious script is stored on the server (e.g., in a comment, profile, or database) and served to other users
- **DOM-based XSS**: Vulnerability exists in client-side code; the server may not see the payload

## Impact
- Session hijacking (stealing cookies / tokens)
- Account takeover
- Defacement
- Phishing / keylogging
- Malware distribution
- CSRF attacks amplified by XSS

## How to Detect in Code
Look for:
- User input (request parameters, headers, cookies, database values) inserted into HTML without encoding
- Use of `innerHTML`, `document.write`, or similar with untrusted data
- Template engines with auto-escaping disabled
- Missing Content-Security-Policy (CSP)

## Prevention
- Context-aware output encoding (HTML, JavaScript, URL, CSS contexts are different)
- Prefer frameworks that auto-escape by default
- Use a strict Content-Security-Policy
- Validate and sanitize input on the server (defense in depth)
- Avoid placing untrusted data into JavaScript, event handlers, or CSS

## Related OWASP
A03:2021 – Injection (XSS is included in the Injection category)

## Example Vulnerable Code
```python
# Flask example – reflected XSS
@app.route("/search")
def search():
    q = request.args.get("q", "")
    return f"<h1>Results for {q}</h1>"   # no encoding
```

## Secure Code
```python
from markupsafe import escape
@app.route("/search")
def search():
    q = request.args.get("q", "")
    return f"<h1>Results for {escape(q)}</h1>"
```
