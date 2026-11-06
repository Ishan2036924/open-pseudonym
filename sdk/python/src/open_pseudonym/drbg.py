"""A small deterministic random source.

Every choice the library makes (which fake name, which test card, how far to shift dates) comes from here. Given the
same seed, Python and TypeScript make exactly the same choices, which is what lets both SDKs share test vectors.

The construction is plain HMAC-SHA256 in counter mode: block(label, n) = HMAC(seed, label || 0x00 || n as 8 bytes).
Each label keeps its own counter, so adding a new kind of choice never shifts the existing ones.
"""

from __future__ import annotations

import hashlib
import hmac

_TWO_64 = 1 << 64


class Drbg:
    def __init__(self, seed: bytes, counters: dict[str, int] | None = None):
        if len(seed) < 16:
            raise ValueError("the seed must be at least 16 bytes")
        self._seed = seed
        self.counters: dict[str, int] = dict(counters or {})

    def block(self, label: str) -> bytes:
        n = self.counters.get(label, 0)
        self.counters[label] = n + 1
        msg = label.encode("utf-8") + b"\x00" + n.to_bytes(8, "big")
        return hmac.new(self._seed, msg, hashlib.sha256).digest()

    def below(self, label: str, n: int) -> int:
        """A uniform integer in [0, n). Rejection sampling keeps it unbiased."""
        if n <= 0:
            raise ValueError("n must be positive")
        limit = (_TWO_64 // n) * n
        while True:
            x = int.from_bytes(self.block(label)[:8], "big")
            if x < limit:
                return x % n

    def derive(self, purpose: str) -> bytes:
        """A key for one purpose, fixed for the life of the seed (does not touch any counter)."""
        return hmac.new(self._seed, b"opn-derive\x00" + purpose.encode("utf-8"), hashlib.sha256).digest()
