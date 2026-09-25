"""Precheck fixture: division without guard from stdin input."""

import sys

line = sys.stdin.readline()
n = int(line.strip())
print(1 // n)
