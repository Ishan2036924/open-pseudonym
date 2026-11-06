"""Format-preserving encryption: NIST SP 800-38G FF1 with AES.

FF1 turns a string of digits into another string of digits of the same length, and back again with the key. We use
it for values where a downstream system checks the shape (a 16-digit card field, a 9-digit routing field) and the
model never needs the real number. NIST's 2025 draft revision drops FF3, so FF1 is the only mode here.

Plain text and output are lists of numerals (0..radix-1). Lengths must satisfy radix**len >= 1,000,000.
"""

from __future__ import annotations

import math

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class FF1:
    def __init__(self, key: bytes, radix: int = 10):
        if len(key) not in (16, 24, 32):
            raise ValueError("FF1 keys are 16, 24 or 32 bytes")
        if not 2 <= radix <= 65536:
            raise ValueError("radix must be between 2 and 65536")
        self._key = key
        self.radix = radix

    def _aes(self, block: bytes) -> bytes:
        enc = Cipher(algorithms.AES(self._key), modes.ECB()).encryptor()
        return enc.update(block) + enc.finalize()

    def _prf(self, data: bytes) -> bytes:
        # CBC-MAC with a zero IV, as the standard defines it
        y = bytes(16)
        for i in range(0, len(data), 16):
            y = self._aes(bytes(a ^ b for a, b in zip(y, data[i:i + 16])))
        return y

    def _num(self, xs: list[int]) -> int:
        n = 0
        for x in xs:
            n = n * self.radix + x
        return n

    def _str(self, n: int, length: int) -> list[int]:
        out = [0] * length
        for i in range(length - 1, -1, -1):
            n, out[i] = divmod(n, self.radix)
        return out

    def _round_values(self, n: int, tweak: bytes):
        u, v = n // 2, n - n // 2
        b = math.ceil(math.ceil(v * math.log2(self.radix)) / 8)
        d = 4 * math.ceil(b / 4) + 4
        p = bytes([1, 2, 1]) + self.radix.to_bytes(3, "big") + bytes([10, u % 256]) + n.to_bytes(4, "big") + len(
            tweak
        ).to_bytes(4, "big")
        return u, v, b, d, p

    def _f(self, p: bytes, tweak: bytes, i: int, half: list[int], b: int, d: int) -> int:
        q = tweak + bytes((-len(tweak) - b - 1) % 16) + bytes([i]) + self._num(half).to_bytes(b, "big")
        r = self._prf(p + q)
        s = r
        j = 1
        while len(s) < d:
            s += self._aes(bytes(x ^ y for x, y in zip(r, j.to_bytes(16, "big"))))
            j += 1
        return int.from_bytes(s[:d], "big")

    def _check(self, xs: list[int]) -> None:
        if self.radix ** len(xs) < 1_000_000:
            raise ValueError("input too short for FF1 (radix**length must be at least 1,000,000)")
        if any(not 0 <= x < self.radix for x in xs):
            raise ValueError("numeral out of range")

    def encrypt(self, xs: list[int], tweak: bytes = b"") -> list[int]:
        self._check(xs)
        n = len(xs)
        u, v, b, d, p = self._round_values(n, tweak)
        a, bb = xs[:u], xs[u:]
        for i in range(10):
            y = self._f(p, tweak, i, bb, b, d)
            m = u if i % 2 == 0 else v
            c = (self._num(a) + y) % (self.radix ** m)
            a, bb = bb, self._str(c, m)
        return a + bb

    def decrypt(self, xs: list[int], tweak: bytes = b"") -> list[int]:
        self._check(xs)
        n = len(xs)
        u, v, b, d, p = self._round_values(n, tweak)
        a, bb = xs[:u], xs[u:]
        for i in range(9, -1, -1):
            y = self._f(p, tweak, i, a, b, d)
            m = u if i % 2 == 0 else v
            c = (self._num(bb) - y) % (self.radix ** m)
            bb, a = a, self._str(c, m)
        return a + bb

    # Digit-string helpers, the only way the rest of the library uses FF1.

    def encrypt_digits(self, digits: str, tweak: bytes = b"") -> str:
        return "".join(str(x) for x in self.encrypt([int(c) for c in digits], tweak))

    def decrypt_digits(self, digits: str, tweak: bytes = b"") -> str:
        return "".join(str(x) for x in self.decrypt([int(c) for c in digits], tweak))
