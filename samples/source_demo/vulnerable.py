"""Intentionally vulnerable local-only sample for VulnAgent demonstrations."""

import os
import pickle
import sqlite3


def command_injection() -> int:
    """Pass untrusted terminal input to a shell sink."""
    command = input("command: ")
    return os.system(command)


def sql_injection(connection: sqlite3.Connection) -> None:
    """Build a query from untrusted input."""
    username = input("username: ")
    connection.execute(f"SELECT * FROM users WHERE name = '{username}'")


def path_traversal() -> str:
    """Open an unbounded user-selected path."""
    requested_path = input("path: ")
    with open(requested_path, encoding="utf-8") as handle:
        return handle.read()


def unsafe_deserialization() -> object:
    """Deserialize untrusted bytes with pickle."""
    payload = input("payload: ").encode()
    return pickle.loads(payload)
