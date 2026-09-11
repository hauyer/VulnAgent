"""CWE-89 positive fixture; static analysis only."""

import sqlite3


def find_user(connection: sqlite3.Connection) -> None:
    username = input("username: ")
    connection.execute(f"SELECT * FROM users WHERE name = '{username}'")
