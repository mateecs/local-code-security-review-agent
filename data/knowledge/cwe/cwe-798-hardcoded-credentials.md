# CWE-798: Use of Hard-coded Credentials

## Description
The software contains hard-coded credentials, such as a password or cryptographic key, which it uses for its own authentication, for communication with external components, or to encrypt data.

Hard-coded credentials are extremely common and frequently lead to full compromise when the source code or binary is obtained.

## Common Locations
- Source code (Python, JavaScript, Java, etc.)
- Configuration files committed to version control
- Mobile applications (easily reverse-engineered)
- Docker images and container environment variables
- Scripts and automation tools
- Default passwords left unchanged

## Impact
- Complete authentication bypass
- Unauthorized access to databases, APIs, cloud services
- Lateral movement inside the network
- Data breaches

## How to Detect in Code
Look for:
- String literals that look like passwords, API keys, tokens, or private keys
- Variables named `password`, `secret`, `api_key`, `token`, `private_key` assigned constant values
- Credentials in comments or documentation
- `.env` files or config files containing real secrets that are committed

## Prevention
- Never hard-code secrets in source code
- Use environment variables, secret managers (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, etc.), or platform secret stores
- Rotate credentials regularly
- Scan repositories with secret-detection tools (gitleaks, trufflehog, GitHub secret scanning)
- Use short-lived credentials and identity federation where possible

## Related OWASP / CWEs
A02:2021 – Cryptographic Failures, CWE-259 (Hard-coded Password), CWE-321 (Hard-coded Cryptographic Key)

## Example Vulnerable Code
```python
# Extremely common anti-pattern
DB_PASSWORD = "SuperSecret123!"
API_KEY = "sk-1234567890abcdef"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
```

## Secure Approach
```python
import os
DB_PASSWORD = os.environ["DB_PASSWORD"]
API_KEY = os.environ["API_KEY"]

# Or better – use a secret manager client
```
