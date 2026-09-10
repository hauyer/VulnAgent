"""Safe counterexamples paired with the intentionally vulnerable sample."""

import json
import sqlite3
import subprocess
from pathlib import Path

BASE_DIRECTORY = Path(__file__).resolve().parent / "data"


def parameterized_query(connection: sqlite3.Connection, username: str) -> None:
    connection.execute("SELECT * FROM users WHERE name = ?", (username,))


def bounded_command(argument: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["python", "-V", argument], shell=False, check=False, text=True)


def bounded_path(name: str) -> str:
    candidate = (BASE_DIRECTORY / name).resolve()
    candidate.relative_to(BASE_DIRECTORY)
    return candidate.read_text(encoding="utf-8")


def safe_deserialization(payload: str) -> object:
    return json.loads(payload)
