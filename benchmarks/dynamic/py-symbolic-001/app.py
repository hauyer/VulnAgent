"""V0.9 symbolic-validation counterpart: unbounded copy loop.

Equivalent runtime semantics of ``gets -> strcpy(dst16, src)`` in Python:
copy every input byte into a fixed 16-byte buffer without a bounds check.
An input longer than 16 bytes raises IndexError — the dynamic proof for the
symbolically-reachable strcpy callsite.
"""

import sys


def main() -> int:
    data = sys.stdin.buffer.read().rstrip(b"\n")
    buffer = bytearray(16)  # fixed-size destination (CWE-121)
    for index, byte in enumerate(data):  # unbounded copy loop
        buffer[index] = byte  # IndexError when len(data) > 16
    print(len(buffer))
    return 0


main()
