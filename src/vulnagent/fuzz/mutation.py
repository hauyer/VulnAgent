"""Simple and reproducible fuzz input mutation strategies."""

from __future__ import annotations

import random


class MutationEngine:
    """Generate small mutations from a seed input."""

    def __init__(self, seed: int = 0) -> None:
        self.random = random.Random(seed)

    def mutate(self, data: bytes, count: int = 8) -> list[bytes]:
        """Generate mutated inputs from one seed."""
        if not data:
            return [b"" for _ in range(count)]

        results: list[bytes] = []

        for _ in range(count):
            mutated = bytearray(data)

            mutation_type = self.random.choice(
                [
                    "bit_flip",
                    "byte_replace",
                    "byte_delete",
                    "byte_insert",
                ]
            )

            if mutation_type == "bit_flip":
                index = self.random.randrange(len(mutated))
                bit = 1 << self.random.randrange(8)
                mutated[index] ^= bit

            elif mutation_type == "byte_replace":
                index = self.random.randrange(len(mutated))
                mutated[index] = self.random.randrange(256)

            elif mutation_type == "byte_delete":
                if len(mutated) > 1:
                    index = self.random.randrange(len(mutated))
                    del mutated[index]

            elif mutation_type == "byte_insert":
                index = self.random.randrange(len(mutated) + 1)
                mutated.insert(index, self.random.randrange(256))

            results.append(bytes(mutated))

        return results