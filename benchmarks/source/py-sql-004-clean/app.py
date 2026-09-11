"""CWE-89 near-pair retaining data in a bound SQL parameter."""

import sqlite3


def lookup_statement() -> str:
    return "SELECT * FROM users WHERE name = ?"


def find_user(connection: sqlite3.Connection) -> None:
    username = input("username: ")
    connection.execute(lookup_statement(), (username,))
