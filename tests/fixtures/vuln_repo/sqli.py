"""Intentionally vulnerable sample: SQL injection (CWE-89)."""


def find_user(cursor, username):
    # String concatenation into a SQL query.
    cursor.execute("SELECT * FROM users WHERE name = '" + username + "'")
    return cursor.fetchone()
