"""Compact JWS with Ed25519 (RFC 7515 + RFC 8037), only what egress receipts need.

The protected header is exactly {"alg": "EdDSA", "kid": ..., "typ": ...}, serialised canonically, so the same receipt
signed in Python and TypeScript is byte-for-byte identical (Ed25519 signatures are deterministic).
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .jcs import b64url, b64url_decode, canonical, digest


class SignatureError(Exception):
    pass


def public_jwk(pub: Ed25519PublicKey) -> dict:
    raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {"crv": "Ed25519", "kty": "OKP", "x": b64url(raw)}


def key_id(pub: Ed25519PublicKey) -> str:
    """RFC 7638 thumbprint of the public key, in our digest format."""
    return digest(canonical(public_jwk(pub)))


@dataclass
class Signer:
    private_key: Ed25519PrivateKey

    @classmethod
    def generate(cls) -> "Signer":
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_seed(cls, seed: bytes) -> "Signer":
        """Deterministic keys for tests and vectors only. Real keys come from generate()."""
        return cls(Ed25519PrivateKey.from_private_bytes(seed))

    @classmethod
    def from_pem(cls, pem: bytes) -> "Signer":
        key = serialization.load_pem_private_key(pem, password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("expected an Ed25519 private key")
        return cls(key)

    def to_pem(self) -> bytes:
        return self.private_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self.private_key.public_key()

    @property
    def kid(self) -> str:
        return key_id(self.public_key)

    def sign(self, payload: dict, typ: str) -> str:
        header = {"alg": "EdDSA", "kid": self.kid, "typ": typ}
        signing_input = b64url(canonical(header)) + "." + b64url(canonical(payload))
        sig = self.private_key.sign(signing_input.encode("ascii"))
        return signing_input + "." + b64url(sig)


def public_key_from_pem(pem: bytes) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(pem)
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("expected an Ed25519 public key")
    return key


def public_pem(pub: Ed25519PublicKey) -> bytes:
    return pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def verify(token: str, pub: Ed25519PublicKey, typ: str) -> dict:
    """Check a compact JWS and return its payload. Raises SignatureError with a short reason."""
    parts = token.split(".")
    if len(parts) != 3:
        raise SignatureError("malformed: a compact JWS has three parts")
    try:
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
        sig = b64url_decode(parts[2])
    except ValueError as exc:
        raise SignatureError("malformed: bad base64url or JSON") from exc
    if set(header) != {"alg", "kid", "typ"} or header["alg"] != "EdDSA":
        raise SignatureError("malformed: unexpected header")
    if header["typ"] != typ:
        raise SignatureError(f"wrong type: expected {typ}")
    if header["kid"] != key_id(pub):
        raise SignatureError("unknown key")
    try:
        canonical_ok = parts[0] == b64url(canonical(header)) and parts[1] == b64url(canonical(payload))
    except TypeError:  # floats or other values we never sign
        canonical_ok = False
    if not canonical_ok:
        raise SignatureError("malformed: not canonical JSON")
    try:
        pub.verify(sig, (parts[0] + "." + parts[1]).encode("ascii"))
    except Exception as exc:  # cryptography raises InvalidSignature
        raise SignatureError("bad signature") from exc
    return payload
