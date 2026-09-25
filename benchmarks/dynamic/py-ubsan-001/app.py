"""V0.8 Dynamic Confirmation benchmark: unvalidated numeric input.

Reads an integer from stdin and lets it reach a fixed-size buffer index
(CWE-193 unchecked index) and a division (CWE-369 divide-by-zero).  The
runtime precheck emits candidates; the Python fuzz backend confirms them
with a real crash.
"""

import sys


def main() -> int:
    line = sys.stdin.readline()
    n = int(line.strip())
    data = [0, 0]  # fixed-size buffer
    data[n] = 1  # CWE-193 / CWE-129: unchecked input index
    print(1 // n)  # CWE-369: divide by zero when n == 0
    return 0


main()
