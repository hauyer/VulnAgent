"""Small local target used only for Fuzz Engine tests."""

from __future__ import annotations

import sys


def main() -> None:
    data = sys.stdin.buffer.read()

    print(f"received {len(data)} bytes")

    if b"CRASH" in data:
        print("intentional test crash", file=sys.stderr)
        raise RuntimeError("intentional test crash")


if __name__ == "__main__":
    main()