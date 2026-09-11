"""CWE-89 negative fixture."""

import sqlite3


def find_user(connection: sqlite3.Connection, username: str) -> None:
    connection.execute("SELECT * FROM users WHERE name = ?", (username,))
