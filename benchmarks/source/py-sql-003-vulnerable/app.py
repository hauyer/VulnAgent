"""CWE-89 helper-return propagation fixture; static analysis only."""

import sqlite3


def build_lookup(username: str) -> str:
    return "SELECT * FROM users WHERE name = '" + username + "'"


def find_user(connection: sqlite3.Connection) -> None:
    query = build_lookup(input("username: "))
    connection.execute(query)
