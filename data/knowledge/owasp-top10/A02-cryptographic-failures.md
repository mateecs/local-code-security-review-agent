# A02:2021 – Cryptographic Failures

## Overview
Previously called "Sensitive Data Exposure". Focuses on failures related to cryptography (or lack of it) that lead to exposure of sensitive data. Ranked #2 in OWASP Top 10 2021.

Sensitive data includes passwords, credit cards, health records, personal information, and business secrets. These often fall under regulations such as GDPR or PCI DSS.

## Common Failures
- Transmitting data in clear text (HTTP, FTP, SMTP without TLS)
- Using old or weak cryptographic algorithms (MD5, SHA-1, DES, RC4)
- Hard-coded or default cryptographic keys
- Weak or reused keys, missing key rotation
- Missing or improper certificate validation
- Insecure modes of operation (ECB)
- Using passwords directly as cryptographic keys without key derivation
- Insufficient entropy / predictable random numbers
- Storing passwords with unsalted or fast hashes
- Deprecated padding schemes (PKCS#1 v1.5)

## How to Detect in Code
Look for:
- Hardcoded secrets, API keys, passwords, or encryption keys in source
- Use of `md5`, `sha1`, `DES`, `RC4`, or weak ciphers
- Password hashing without salt or with fast algorithms
- HTTP instead of HTTPS for sensitive endpoints
- Missing HSTS headers
- Custom cryptography implementations
- Predictable seeds for random number generators

## Prevention
- Classify data and identify what needs protection
- Do not store sensitive data unnecessarily
- Encrypt all sensitive data at rest
- Use strong, up-to-date algorithms and proper key management
- Encrypt all data in transit with TLS (forward secrecy, secure parameters)
- Enforce HTTPS with HSTS
- Store passwords with adaptive, salted hashing: Argon2, scrypt, bcrypt, or PBKDF2
- Use authenticated encryption (not just encryption)
- Generate keys cryptographically randomly; never hard-code them
- Avoid deprecated functions (MD5, SHA-1, PKCS#1 v1.5)
- Verify configuration independently

## Related CWEs
CWE-259 (Hard-coded Password), CWE-321 (Hard-coded Cryptographic Key), CWE-327 (Broken/Risky Crypto Algorithm), CWE-330 (Insufficiently Random Values), CWE-331 (Insufficient Entropy), CWE-759 (Hash without Salt), CWE-916 (Password Hash with Insufficient Effort)

## Example Vulnerable Patterns
```python
# Bad – hardcoded secret
SECRET_KEY = "my-super-secret-key-123"

# Bad – weak hashing
import hashlib
hashed = hashlib.md5(password.encode()).hexdigest()

# Bad – cleartext transmission
requests.get("http://api.example.com/user-data")
```

## Secure Patterns
```python
# Good – use environment / secret manager
import os
SECRET_KEY = os.environ["SECRET_KEY"]

# Good – strong password hashing
import bcrypt
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))

# Good – force HTTPS
# Use HSTS and redirect HTTP → HTTPS
```
