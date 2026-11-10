// The vault: the only place where real values and their stand-ins sit side by side.
//
// It never leaves the device (or the app's own server). When saved, it is encrypted with AES-256-GCM under a key the
// app keeps; the EDPB treats this table as personal data in its own right, so we treat it like one.
//
// An entry is one real value under one action. Each entry remembers every surface form it was shown as
// (`surfaces`: stand-in text -> the real text it replaced), so restoring puts back exactly what the person wrote.

import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import * as fs from "node:fs";
import { Drbg } from "./drbg.ts";
import { b64url, b64urlDecode } from "./jcs.ts";
import { cmpCodePoints } from "./util.ts";

const AAD = Buffer.from("opn-vault-v1");

export class VaultError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "VaultError";
  }
}

function sortedList(items: Iterable<string>): string[] {
  return [...items].sort(cmpCodePoints);
}

// Maps keep insertion order whatever the keys look like (a plain object would move "123" to the front), so they
// are used wherever the order of entries can change a result.
function mapToObject<V>(m: Map<string, V>): Record<string, V> {
  return Object.fromEntries(m);
}

function objectToMap<V>(o: Record<string, V> | null | undefined): Map<string, V> {
  return new Map(Object.entries(o ?? {}));
}

export class Entry {
  id: string;
  type: string;
  real: string;
  norm: string;
  action: string;
  standIn: string;
  restorable: boolean;
  surfaces: Map<string, string>; // stand-in surface -> real surface
  meta: Record<string, any>;

  constructor(id: string, type: string, real: string, norm: string, action: string, standIn: string,
    restorable: boolean, surfaces: Map<string, string> = new Map(), meta: Record<string, any> = {}) {
    this.id = id;
    this.type = type;
    this.real = real;
    this.norm = norm;
    this.action = action;
    this.standIn = standIn;
    this.restorable = restorable;
    this.surfaces = surfaces;
    this.meta = meta;
  }

  toJSON(): Record<string, any> {
    return {
      id: this.id, type: this.type, real: this.real, norm: this.norm, action: this.action,
      stand_in: this.standIn, restorable: this.restorable, surfaces: mapToObject(this.surfaces), meta: this.meta,
    };
  }

  static fromJSON(d: Record<string, any>): Entry {
    return new Entry(d.id, d.type, d.real, d.norm, d.action, d.stand_in, d.restorable, objectToMap(d.surfaces),
      { ...(d.meta ?? {}) });
  }
}

export class Vault {
  seed: Uint8Array;
  drbg: Drbg;
  created: number;
  entries: Entry[] = [];
  private index = new Map<string, Entry>();
  used = new Set<string>(); // every stand-in we ever issued, lower case
  realSeen = new Set<string>(); // real values and real name parts, lower case
  parts = new Map<string, string>(); // real name part (lower) -> fake part
  partsBack = new Map<string, string>(); // fake name part (lower) -> real part as first written
  domains = new Map<string, string>(); // real registrable domain (lower) -> fake domain
  numbers = new Map<string, number>(); // per type counter for [TYPE_n] and {{TYPE_n}}
  dateOffset: number | null = null; // days, a non-zero multiple of 7
  moneyFactor: number | null = null;
  tokenKey: Uint8Array | null = null; // set it to keep tokens stable across vaults
  fpeKey: Uint8Array | null = null;
  version = 0; // bumps on every change, so caches know when to rebuild

  constructor(seed?: Uint8Array | null, created?: number | null) {
    this.seed = seed ?? randomBytes(32);
    this.drbg = new Drbg(this.seed);
    this.created = created ?? Math.floor(Date.now() / 1000);
  }

  private static key(type: string, norm: string, action: string): string {
    return JSON.stringify([type, norm, action]);
  }

  // Lookups

  find(type: string, norm: string, action: string): Entry | undefined {
    return this.index.get(Vault.key(type, norm, action));
  }

  byId(entryId: string): Entry | undefined {
    return this.entries.find((e) => e.id === entryId);
  }

  isStandIn(text: string): boolean {
    return this.used.has(text.toLowerCase());
  }

  // Changes

  add(type: string, real: string, norm: string, action: string, standIn: string, restorable: boolean,
    meta: Record<string, any> = {}): Entry {
    const entry = new Entry(`e${this.entries.length + 1}`, type, real, norm, action, standIn, restorable,
      new Map([[standIn, real]]), meta);
    this.entries.push(entry);
    this.index.set(Vault.key(type, norm, action), entry);
    this.used.add(standIn.toLowerCase());
    this.realSeen.add(real.toLowerCase());
    this.version += 1;
    return entry;
  }

  addSurface(entry: Entry, standIn: string, real: string): void {
    if (entry.surfaces.get(standIn) !== real) {
      if (!entry.surfaces.has(standIn)) entry.surfaces.set(standIn, real);
      this.used.add(standIn.toLowerCase());
      this.version += 1;
    }
  }

  addPart(realPart: string, fakePart: string): void {
    const key = realPart.toLowerCase();
    if (!this.parts.has(key)) {
      this.parts.set(key, fakePart);
      if (!this.partsBack.has(fakePart.toLowerCase())) this.partsBack.set(fakePart.toLowerCase(), realPart);
      this.used.add(fakePart.toLowerCase());
      this.realSeen.add(key);
      this.version += 1;
    }
  }

  nextNumber(type: string): number {
    const n = (this.numbers.get(type) ?? 0) + 1;
    this.numbers.set(type, n);
    return n;
  }

  touch(): void {
    this.version += 1;
  }

  // Values drawn once per vault

  getDateOffset(): number {
    if (this.dateOffset === null) {
      let weeks = this.drbg.below("date.offset", 16) - 8; // -8 .. 7
      if (weeks >= 0) weeks += 1; // never zero: -8..-1 and 1..8 weeks, so the season stays
      this.dateOffset = 7 * weeks; // whole weeks keep the weekday
      this.version += 1;
    }
    return this.dateOffset;
  }

  getMoneyFactor(): number {
    if (this.moneyFactor === null) {
      this.moneyFactor = 2 + this.drbg.below("money.factor", 3); // 2, 3 or 4: whole cents stay whole
      this.version += 1;
    }
    return this.moneyFactor;
  }

  getTokenKey(): Uint8Array {
    return this.tokenKey ?? this.drbg.derive("token");
  }

  getFpeKey(): Uint8Array {
    return this.fpeKey ?? this.drbg.derive("fpe");
  }

  // Saving

  toJSON(): Record<string, any> {
    return {
      opn: "0.1",
      type: "vault-state",
      seed: b64url(this.seed),
      created: this.created,
      counters: mapToObject(this.drbg.counters),
      entries: this.entries.map((e) => e.toJSON()),
      used: sortedList(this.used),
      real_seen: sortedList(this.realSeen),
      parts: mapToObject(this.parts),
      parts_back: mapToObject(this.partsBack),
      domains: mapToObject(this.domains),
      numbers: mapToObject(this.numbers),
      date_offset: this.dateOffset,
      money_factor: this.moneyFactor,
      token_key: this.tokenKey && this.tokenKey.length > 0 ? b64url(this.tokenKey) : null,
      fpe_key: this.fpeKey && this.fpeKey.length > 0 ? b64url(this.fpeKey) : null,
    };
  }

  static fromJSON(d: Record<string, any>): Vault {
    if (d?.type !== "vault-state") throw new VaultError("not a vault state document");
    const v = new Vault(b64urlDecode(d.seed), d.created);
    v.drbg = new Drbg(v.seed, d.counters);
    for (const raw of d.entries ?? []) {
      const e = Entry.fromJSON(raw);
      v.entries.push(e);
      v.index.set(Vault.key(e.type, e.norm, e.action), e);
    }
    v.used = new Set(d.used ?? []);
    v.realSeen = new Set(d.real_seen ?? []);
    v.parts = objectToMap(d.parts);
    v.partsBack = objectToMap(d.parts_back);
    v.domains = objectToMap(d.domains);
    v.numbers = objectToMap(d.numbers);
    v.dateOffset = d.date_offset ?? null;
    v.moneyFactor = d.money_factor ?? null;
    v.tokenKey = d.token_key ? b64urlDecode(d.token_key) : null;
    v.fpeKey = d.fpe_key ? b64urlDecode(d.fpe_key) : null;
    return v;
  }

  encrypt(key: Uint8Array): Buffer {
    if (key.length !== 32) throw new VaultError("the vault key must be 32 bytes");
    const nonce = randomBytes(12);
    const body = Buffer.from(JSON.stringify(this.toJSON()), "utf-8");
    const cipher = createCipheriv("aes-256-gcm", key, nonce);
    cipher.setAAD(AAD);
    // like most AEAD libraries, the 16-byte tag goes straight after the ciphertext
    const ct = Buffer.concat([cipher.update(body), cipher.final(), cipher.getAuthTag()]);
    const doc = { opn: "0.1", type: "vault", alg: "A256GCM", nonce: b64url(nonce), ciphertext: b64url(ct) };
    return Buffer.from(JSON.stringify(doc), "utf-8");
  }

  static decrypt(blob: Uint8Array, key: Uint8Array): Vault {
    let body: Buffer;
    try {
      const doc = JSON.parse(Buffer.from(blob).toString("utf-8"));
      if (doc?.type !== "vault" || doc?.alg !== "A256GCM") throw new VaultError("not an encrypted vault");
      const raw = b64urlDecode(doc.ciphertext);
      const decipher = createDecipheriv("aes-256-gcm", key, b64urlDecode(doc.nonce));
      decipher.setAAD(AAD);
      decipher.setAuthTag(raw.subarray(raw.length - 16));
      body = Buffer.concat([decipher.update(raw.subarray(0, raw.length - 16)), decipher.final()]);
    } catch (exc) {
      if (exc instanceof VaultError) throw exc;
      throw new VaultError("could not open the vault (wrong key or damaged file)"); // wrong key, damaged file
    }
    return Vault.fromJSON(JSON.parse(body.toString("utf-8")));
  }

  /** Write atomically with owner-only permissions. */
  save(path: string, key: Uint8Array): void {
    const tmp = path + ".tmp";
    const fd = fs.openSync(tmp, "w", 0o600);
    try {
      fs.writeSync(fd, this.encrypt(key));
    } finally {
      fs.closeSync(fd);
    }
    fs.renameSync(tmp, path);
  }

  static load(path: string, key: Uint8Array): Vault {
    return Vault.decrypt(fs.readFileSync(path), key);
  }
}
