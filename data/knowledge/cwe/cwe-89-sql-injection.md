# CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

## Description
The software constructs all or part of an SQL command using externally-influenced input without neutralizing special elements that can modify the intended SQL command.

SQL Injection remains one of the most dangerous and common weaknesses (consistently in CWE Top 25).

## Impact
- Authentication bypass
- Reading, modifying, or deleting arbitrary data
- Reading sensitive data (passwords, PII, financial records)
- Remote code execution (in some database configurations)
- Complete compromise of the database server

## How to Detect in Code
Look for:
- String concatenation, f-strings, or format() used to build SQL queries
- Dynamic table or column names taken from user input
- Use of `execute()` with a single string argument containing user data
- ORM methods that still allow raw SQL with concatenation

## Prevention
- Always use parameterized queries / prepared statements
- Prefer ORMs or query builders that parameterize by default
- Never concatenate user input into SQL
- Apply least privilege to the database account used by the application
- Input validation is a secondary control, not a primary defense

## Related OWASP
A03:2021 – Injection

## Example Vulnerable Code
```python
# Classic SQL Injection
user_id = request.args.get("id")
query = f"SELECT * FROM users WHERE id = '{user_id}'"
cursor.execute(query)

# Another bad pattern
query = "SELECT * FROM users WHERE name = '" + name + "'"
```

## Secure Code
```python
# Parameterized query (psycopg2 / MySQL Connector style)
user_id = request.args.get("id")
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

# SQLAlchemy example
user = session.query(User).filter(User.id == user_id).one_or_none()
```
