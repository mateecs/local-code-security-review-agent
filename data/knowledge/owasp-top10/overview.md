# OWASP Top 10:2021 – Overview for Security Agents

The OWASP Top 10 is the standard awareness document for the most critical web application security risks.

## 2021 Ranking
1. **A01 Broken Access Control** – Most serious; highest occurrences
2. **A02 Cryptographic Failures** – Failures in crypto leading to data exposure
3. **A03 Injection** – SQL, XSS, Command, LDAP, etc.
4. **A04 Insecure Design** – Missing or ineffective control design
5. **A05 Security Misconfiguration** – Hardening, defaults, verbose errors
6. **A06 Vulnerable and Outdated Components** – Unpatched libraries and software
7. **A07 Identification and Authentication Failures** – Broken auth and session management
8. **A08 Software and Data Integrity Failures** – Insecure CI/CD, unsigned updates, insecure deserialization
9. **A09 Security Logging and Monitoring Failures** – Missing detection and response
10. **A10 Server-Side Request Forgery (SSRF)**

## Guidance for an AI Security Agent
When analyzing code, prioritize findings that map to A01–A03 and A05 first. Always require concrete evidence (file + line + snippet). Prefer reporting:
- Missing authorization checks
- SQL / command injection via string concatenation
- XSS via unencoded output
- Hardcoded secrets
- Debug mode or verbose errors in production configs
- Path traversal in file operations
- Weak or missing cryptography

For every finding, include:
- Severity estimate
- Exact location
- Why it is dangerous
- Concrete remediation
- Related CWE / OWASP category
- Confidence level
