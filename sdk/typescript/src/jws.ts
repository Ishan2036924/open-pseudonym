// Compact JWS with Ed25519 (RFC 7515 + RFC 8037), only what egress receipts need.
//
// The protected header is exactly {"alg": "EdDSA", "kid": ..., "typ": ...}, serialised canonically, so the same receipt
// signed in Python and TypeScript is byte-for-byte identical (Ed25519 signatures are deterministic).

import {
  createPrivateKey, createPublicKey, generateKeyPairSync, sign as edSign, verify as edVerify,
  type KeyObject,
} from "node:crypto";
import { b64url, b64urlDecode, canonical, digest } from "./jcs.ts";

export class SignatureError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SignatureError";
  }
}

// The fixed bytes in front of a raw 32-byte Ed25519 seed that make it a PKCS#8 private key.
const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

export function publicJwk(pub: KeyObject): { crv: string; kty: string; x: string } {
  const jwk = pub.export({ format: "jwk" });
  return { crv: "Ed25519", kty: "OKP", x: jwk.x as string };
}

/** RFC 7638 thumbprint of the public key, in our digest format. */
export function keyId(pub: KeyObject): string {
  return digest(canonical(publicJwk(pub)));
}

export class Signer {
  readonly privateKey: KeyObject;

  constructor(privateKey: KeyObject) {
    this.privateKey = privateKey;
  }

  static generate(): Signer {
    return new Signer(generateKeyPairSync("ed25519").privateKey);
  }

  /** Deterministic keys for tests and vectors only. Real keys come from generate(). */
  static fromSeed(seed: Uint8Array): Signer {
    if (seed.length !== 32) throw new RangeError("an Ed25519 seed is 32 bytes");
    const der = Buffer.concat([PKCS8_PREFIX, seed]);
    return new Signer(createPrivateKey({ key: der, format: "der", type: "pkcs8" }));
  }

  static fromPem(pem: string | Uint8Array): Signer {
    const key = createPrivateKey(Buffer.from(pem));
    if (key.asymmetricKeyType !== "ed25519") throw new TypeError("expected an Ed25519 private key");
    return new Signer(key);
  }

  toPem(): string {
    return this.privateKey.export({ type: "pkcs8", format: "pem" }) as string;
  }

  get publicKey(): KeyObject {
    return createPublicKey(this.privateKey);
  }

  get kid(): string {
    return keyId(this.publicKey);
  }

  sign(payload: Record<string, unknown>, typ: string): string {
    const header = { alg: "EdDSA", kid: this.kid, typ };
    const signingInput = b64url(canonical(header)) + "." + b64url(canonical(payload));
    const sig = edSign(null, Buffer.from(signingInput, "ascii"), this.privateKey);
    return signingInput + "." + b64url(sig);
  }
}

export function publicKeyFromPem(pem: string | Uint8Array): KeyObject {
  const key = createPublicKey(Buffer.from(pem));
  if (key.asymmetricKeyType !== "ed25519") throw new TypeError("expected an Ed25519 public key");
  return key;
}

export function publicPem(pub: KeyObject): string {
  return pub.export({ type: "spki", format: "pem" }) as string;
}

function parseJson(bytes: Buffer): any {
  try {
    return JSON.parse(bytes.toString("utf-8"));
  } catch {
    throw new SignatureError("malformed: bad base64url or JSON");
  }
}

/** Check a compact JWS and return its payload. Throws SignatureError with a short reason. */
export function verify(token: string, pub: KeyObject, typ: string): Record<string, any> {
  const parts = token.split(".");
  if (parts.length !== 3) throw new SignatureError("malformed: a compact JWS has three parts");
  const header = parseJson(b64urlDecode(parts[0]));
  const payload = parseJson(b64urlDecode(parts[1]));
  const sig = b64urlDecode(parts[2]);
  const keys = header !== null && typeof header === "object" ? Object.keys(header).sort().join(",") : "";
  if (keys !== "alg,kid,typ" || header.alg !== "EdDSA") throw new SignatureError("malformed: unexpected header");
  if (header.typ !== typ) throw new SignatureError(`wrong type: expected ${typ}`);
  if (header.kid !== keyId(pub)) throw new SignatureError("unknown key");
  let canonicalOk = false;
  try {
    canonicalOk = parts[0] === b64url(canonical(header)) && parts[1] === b64url(canonical(payload));
  } catch {
    // a float or another shape we never sign cannot be canonical
  }
  if (!canonicalOk) throw new SignatureError("malformed: not canonical JSON");
  let good = false;
  try {
    good = edVerify(null, Buffer.from(parts[0] + "." + parts[1], "ascii"), pub, sig);
  } catch {
    good = false;
  }
  if (!good) throw new SignatureError("bad signature");
  return payload;
}
