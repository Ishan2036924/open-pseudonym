// Proving what left: the egress check and signed, chained receipts.
//
// The check runs on the exact bytes about to be sent. It first blanks out every stand-in we issued, then looks for any
// real value the vault holds (names, their parts, emails in any case, numbers with any formatting). If it finds one,
// the request is not sent. This proves something narrow and useful: no value we know about left. It cannot prove that
// a value the detectors never saw did not leave, and the receipts say so by counting only what the vault knows.
//
// Each sent request gets a receipt, an Ed25519-signed JWS that names the payload's digest, the policy, how many
// stand-ins of each type were in it, and the previous receipt's digest. `verifyLog` re-checks all of it later.

import type { KeyObject } from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import { KnownDetector, type Form } from "./detect.ts";
import { pools } from "./data.ts";
import { digest } from "./jcs.ts";
import { SignatureError, type Signer, verify } from "./jws.ts";
import { Restorer } from "./restore.ts";
import { CASELESS_TYPES, DIGIT_TYPES, digitsOf } from "./types.ts";
import type { Vault } from "./vault.ts";
import { splitWs, stripWs } from "./util.ts";

export const RECEIPT_TYP = "opn-egress+jws";

export interface Leak {
  type: string;
  entryId: string;
}

export class EgressLeak extends Error {
  readonly leaks: Leak[];

  constructor(leaks: Leak[]) {
    const types = [...new Set(leaks.map((lk) => lk.type))].sort();
    super(`refused to send: ${leaks.length} known value(s) of type ${types.join(", ")} still present`);
    this.name = "EgressLeak";
    this.leaks = leaks;
  }
}

/** The text the check reads. For JSON we read the decoded strings, so 'é' escapes cannot hide a name. */
export function payloadText(payload: Uint8Array | string): string {
  const raw = typeof payload === "string" ? payload : new TextDecoder("utf-8", { ignoreBOM: true }).decode(payload);
  let doc: unknown;
  try {
    doc = JSON.parse(raw);
  } catch {
    return raw;
  }
  // the raw text is always read too, so a bare JSON number or literal is checked as written
  const out: string[] = [raw];
  const walk = (v: unknown): void => {
    if (typeof v === "string") out.push(v);
    else if (Array.isArray(v)) for (const x of v) walk(x);
    else if (v !== null && typeof v === "object") {
      for (const [k, x] of Object.entries(v)) {
        out.push(k);
        walk(x);
      }
    }
  };
  walk(doc);
  return out.join("\n");
}

/** Matches the session's rule: multi-word names in any case, single words as written. */
export function knownMode(type: string, value: string): "case" | "nocase" {
  if (CASELESS_TYPES.has(type) || (["PERSON", "ORG", "LOCATION", "ADDRESS"].includes(type) && splitWs(value).length > 1)) {
    return "nocase";
  }
  return "case";
}

/** Every real value that must never leave, as (type, text, mode) for KnownDetector. */
export function realForms(vault: Vault): Form[] {
  const forms: Form[] = [];
  for (const e of vault.entries) {
    if (e.action === "keep") continue;
    for (const real of new Set([...e.surfaces.values(), e.real])) {
      if (e.type === "IBAN") {
        forms.push([e.type, real, "nocase"]);
        forms.push([e.type, splitWs(real).join(""), "nocase"]);
      } else if (DIGIT_TYPES.has(e.type)) {
        const d = digitsOf(real);
        // long numbers match with any formatting; a short code must match as written
        forms.push(d.length >= 6 ? [e.type, d, "digits"] : [e.type, real, "case"]);
      } else if ([...real].length >= 2) {
        forms.push([e.type, real, knownMode(e.type, real)]);
      }
    }
  }
  // stopword parts ("May") are never masked on their own, so searching for them would only raise false alarms
  const stop = new Set((pools().name_stopwords as string[]).map((w) => w.toLowerCase()));
  for (const realPart of vault.partsBack.values()) {
    if ([...realPart].length >= 3 && !stop.has(realPart.toLowerCase())) forms.push(["PERSON", realPart, "case"]);
  }
  return forms;
}

export function check(vault: Vault, payload: Uint8Array | string, restorer?: Restorer | null): Leak[] {
  const text = payloadText(payload);
  const r = restorer ?? new Restorer(vault);
  // blank out our own stand-ins first, so a fake that happens to equal a real value elsewhere is not a false alarm
  const chars = text.split("");
  for (const m of r.matches(text)) {
    for (let i = m.start; i < m.end; i++) chars[i] = " ";
  }
  const blanked = chars.join("");
  const leaks: Leak[] = [];
  const seen = new Set<string>();
  for (const span of new KnownDetector(realForms(vault)).detect(blanked)) {
    const entry = entryFor(vault, span.type, span.text);
    const key = JSON.stringify([span.type, entry]);
    if (!seen.has(key)) {
      seen.add(key);
      leaks.push({ type: span.type, entryId: entry });
    }
  }
  return leaks;
}

function entryFor(vault: Vault, type: string, text: string): string {
  const low = text.toLowerCase();
  const d = digitsOf(text);
  for (const e of vault.entries) {
    if (e.type !== type) continue;
    const reals = new Set([...e.surfaces.values(), e.real]);
    for (const r of reals) if (r.toLowerCase() === low || (d !== "" && digitsOf(r) === d)) return e.id;
  }
  return "part";
}

/** How many distinct stand-ins of each type the payload carries. */
export function standInCounts(vault: Vault, payload: Uint8Array | string, restorer?: Restorer | null): Record<string, number> {
  const r = restorer ?? new Restorer(vault);
  const ids = new Set<string>();
  for (const m of r.matches(payloadText(payload))) if (m.entryId) ids.add(m.entryId);
  const counts = new Map<string, number>();
  for (const eid of ids) {
    const type = vault.byId(eid)?.type ?? "PERSON";
    counts.set(type, (counts.get(type) ?? 0) + 1);
  }
  return Object.fromEntries([...counts].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)));
}

export interface RecordOptions {
  session: string;
  policyDigest: string;
  dest: string;
  now: number;
  detectors: string[];
  restorer?: Restorer | null;
  allowLeaks?: boolean;
}

// the line breaks Python's str.splitlines() honours
const LINE_BREAKS = /\r\n|[\n\r\v\f\x1c-\x1e\x85\u2028\u2029]/u;

function readLines(file: string): string[] {
  return fs.readFileSync(file, "utf-8").split(LINE_BREAKS).filter((ln) => stripWs(ln) !== "");
}

/**
 * An append-only folder: receipts.jsonl (one JWS per line) and, optionally, the payloads themselves.
 *
 * Payloads are what the model provider received, so they hold stand-ins, not real values. Keeping them lets anyone
 * with the vault re-run the check later; without them a verifier can still check signatures and the chain.
 */
export class EgressLog {
  readonly folder: string;
  readonly signer: Signer;
  readonly storePayloads: boolean;
  private readonly receipts: string;
  seq = 0;
  prev: string | null = null;

  constructor(folder: string, signer: Signer, storePayloads = true) {
    this.folder = folder;
    fs.mkdirSync(folder, { recursive: true });
    this.signer = signer;
    this.storePayloads = storePayloads;
    this.receipts = path.join(folder, "receipts.jsonl");
    if (fs.existsSync(this.receipts)) {
      const lines = readLines(this.receipts);
      if (lines.length > 0) {
        this.seq = lines.length;
        this.prev = digest(Buffer.from(lines[lines.length - 1], "ascii"));
      }
    }
  }

  record(vault: Vault, payload: Uint8Array | string, o: RecordOptions): string {
    const bytes = typeof payload === "string" ? Buffer.from(payload, "utf-8") : payload;
    const restorer = o.restorer ?? new Restorer(vault);
    const leaks = check(vault, bytes, restorer);
    if (leaks.length > 0 && !o.allowLeaks) throw new EgressLeak(leaks);
    const known = vault.entries.filter((e) => e.action !== "keep").length;
    const body = {
      opn: "0.1",
      type: "egress",
      session: o.session,
      seq: this.seq + 1,
      iat: o.now,
      prev: this.prev,
      dest: o.dest,
      payload: digest(bytes),
      policy: o.policyDigest,
      stand_ins: standInCounts(vault, bytes, restorer),
      check: { known_values: known, found: leaks.length },
      detectors: o.detectors,
    };
    const token = this.signer.sign(body, RECEIPT_TYP);
    if (this.storePayloads) {
      const pdir = path.join(this.folder, "payloads");
      fs.mkdirSync(pdir, { recursive: true });
      fs.writeFileSync(path.join(pdir, `${String(this.seq + 1).padStart(6, "0")}.bin`), bytes);
    }
    const fd = fs.openSync(this.receipts, "a");
    try {
      fs.writeSync(fd, token + "\n");
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    this.seq += 1;
    this.prev = digest(Buffer.from(token, "ascii"));
    return token;
  }
}

export interface LogReport {
  receipts: number;
  rechecked: number;
  leaks: number;
  problems: string[];
  /** The digest of the last receipt, to record elsewhere and pass back as `expectLast` later. */
  last: string | null;
}

export interface VerifyOptions {
  /** How many requests were sent, as recorded elsewhere. */
  expectCount?: number | null;
  /** The digest of the last receipt (the x-opn-receipt header the app kept). */
  expectLast?: string | null;
  /** The session id the receipts must belong to, so a log from another session is not taken for this one. */
  expectSession?: string | null;
}

/**
 * Check every receipt: signature, chain, payload digest and (with the vault) the egress check again.
 *
 * A chain proves that nothing in the middle was changed, but not that nothing was cut off the end. To catch that,
 * pass what you recorded elsewhere: the number of requests sent (`expectCount`) or the digest of the last receipt
 * (`expectLast`, from the x-opn-receipt header the app kept). Returns counts and a list of problems; an empty list
 * means the log holds up.
 */
export function verifyLog(folder: string, publicKey: KeyObject, vault?: Vault | null, o: VerifyOptions = {}): LogReport {
  const logFile = path.join(folder, "receipts.jsonl");
  const haveLog = fs.existsSync(logFile);
  const lines = haveLog ? readLines(logFile) : [];
  const problems: string[] = [];
  if (!haveLog) problems.push("there is no receipts.jsonl in this folder");
  const payloadDir = path.join(folder, "payloads");
  const stored = fs.existsSync(payloadDir) && fs.statSync(payloadDir).isDirectory();
  const extra = stored
    ? fs.readdirSync(payloadDir).filter((n) => n.endsWith(".bin") && !(/^[0-9]+$/.test(n.slice(0, -4)) && Number(n.slice(0, -4)) <= lines.length))
    : [];
  if (extra.length > 0) problems.push(`${extra.length} stored payload(s) have no receipt: receipts were removed`);
  let prev: string | null = null;
  let leaksTotal = 0;
  let rechecked = 0;
  const restorer = vault ? new Restorer(vault) : null;
  for (const [idx, token] of lines.entries()) {
    const i = idx + 1;
    let body: Record<string, any>;
    try {
      body = verify(token, publicKey, RECEIPT_TYP);
    } catch (exc) {
      // a damaged line must never stop the rest of the check
      if (exc instanceof SignatureError) problems.push(`receipt ${i}: ${exc.message}`);
      else problems.push(`receipt ${i}: unreadable (${exc instanceof Error ? exc.name : "Error"})`);
      prev = safeDigest(token);
      continue;
    }
    if (o.expectSession != null && body.session !== o.expectSession) problems.push(`receipt ${i}: belongs to another session`);
    if (body.seq !== i) problems.push(`receipt ${i}: sequence number is ${body.seq}`);
    if ((body.prev ?? null) !== prev) problems.push(`receipt ${i}: chain broken (prev does not match receipt ${i - 1})`);
    if (body.check?.found) problems.push(`receipt ${i}: was sent with ${body.check.found} known value(s) present`);
    const pfile = path.join(folder, "payloads", `${String(i).padStart(6, "0")}.bin`);
    if (fs.existsSync(pfile)) {
      const data = fs.readFileSync(pfile);
      if (digest(data) !== body.payload) {
        problems.push(`receipt ${i}: stored payload does not match its digest`);
      } else if (vault) {
        rechecked += 1;
        const found = check(vault, data, restorer);
        leaksTotal += found.length;
        if (found.length > 0) problems.push(`receipt ${i}: ${found.length} known value(s) found on re-check`);
      }
    } else if (stored) {
      problems.push(`receipt ${i}: its stored payload is missing`);
    }
    prev = safeDigest(token);
  }
  if (lines.length === 0 && haveLog) problems.push("the log holds no receipts");
  if (vault && lines.length > 0 && rechecked === 0) {
    problems.push("no stored payloads to re-check: they were never kept, or they were removed");
  }
  if (o.expectCount != null && o.expectCount !== lines.length) {
    problems.push(`expected ${o.expectCount} receipt(s), found ${lines.length}: the log was cut or added to`);
  }
  if (o.expectLast != null && o.expectLast !== prev) {
    problems.push("the last receipt is not the one you recorded: the log was cut or replaced");
  }
  return { receipts: lines.length, rechecked, leaks: leaksTotal, problems, last: prev };
}

function safeDigest(token: string): string {
  return digest(Buffer.from(token, "utf-8"));
}
