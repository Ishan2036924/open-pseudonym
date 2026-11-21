// Proving what left: the egress check and signed, chained receipts.
//
// The check runs on the exact bytes about to be sent. It first blanks out every stand-in we issued, then looks for any
// real value the vault holds (names, their parts, emails in any case, numbers with any formatting). If it finds one,
// the request is not sent. This proves something narrow and useful: no value we know about left. It cannot prove that
// a value the detectors never saw did not leave, and the receipts say so by counting only what the vault knows.
//
// Each sent request gets a receipt, an Ed25519-signed JWS that names the payload's digest, the policy, how many
// stand-ins of each type were in it, and the previous receipt's digest. `verifyLog` re-checks all of it later.
//
// The same log can also hold release records: one signed line for each decision to fill, or to refuse to fill, a
// secret handle, with who allowed it (spec 10.4). A checkpoint is a head of the chain signed by a key the writer does
// not hold; given to `verifyLog` it proves the log was not cut off before that point (spec 11.3).

import type { KeyObject } from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import { ambiguousNames, cueOnly, stopwords } from "./checks.ts";
import { KnownDetector, type Form } from "./detect.ts";
import { CODES, DIGEST, HANDLE } from "./handles.ts";
import { b64urlDecode, canonical, digest } from "./jcs.ts";
import { keyId, SignatureError, type Signer, verify } from "./jws.ts";
import { Restorer } from "./restore.ts";
import { CASELESS_TYPES, DIGIT_TYPES, digitsOf } from "./types.ts";
import type { Vault } from "./vault.ts";
import { splitWs, stripWs } from "./util.ts";

export const RECEIPT_TYP = "opn-egress+jws";
export const RELEASE_TYP = "opn-release+jws";
export const CHECKPOINT_TYP = "opn-checkpoint+jws";
export const AUTHORITY_KINDS = ["binding", "person", "consent", "policy"];

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
      if (cueOnly(e.type, real)) continue;
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
  const stop = new Set([...stopwords(), ...ambiguousNames()]);
  for (const realPart of vault.partsBack.values()) {
    if ([...realPart].length >= 3 && !stop.has(realPart.toLowerCase())) forms.push(["PERSON", realPart, "case"]);
  }
  return forms;
}

/** The text with our own stand-ins replaced by spaces (same length, so positions still line up). */
export function blankStandIns(text: string, restorer: Restorer): string {
  const chars = text.split("");
  for (const m of restorer.matches(text)) {
    for (let i = m.start; i < m.end; i++) chars[i] = " ";
  }
  return chars.join("");
}

export function check(vault: Vault, payload: Uint8Array | string, restorer?: Restorer | null): Leak[] {
  const text = payloadText(payload);
  const r = restorer ?? new Restorer(vault);
  // blank out our own stand-ins first, so a fake that happens to equal a real value elsewhere is not a false alarm
  const blanked = blankStandIns(text, r);
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
    this.append([token]);
    return token;
  }

  /** Sign and append one release record (spec 10.4). See `recordReleases` for the fields. */
  recordRelease(entry: ReleaseEntry): string {
    return this.recordReleases([entry])[0];
  }

  /**
   * Sign and append release records, all in one write, so a call that fills several handles is recorded whole or not
   * at all. There is no field for a value, and none may be added.
   */
  recordReleases(entries: ReleaseEntry[]): string[] {
    let seq = this.seq;
    let prev = this.prev;
    const tokens: string[] = [];
    for (const e of entries) {
      const token = this.signer.sign(releaseBody(e, seq + 1, prev), RELEASE_TYP);
      tokens.push(token);
      seq += 1;
      prev = digest(Buffer.from(token, "ascii"));
    }
    this.append(tokens);
    return tokens;
  }

  private append(tokens: string[]): void {
    try {
      const fd = fs.openSync(this.receipts, "a");
      try {
        fs.writeSync(fd, tokens.map((t) => t + "\n").join(""));
        fs.fsyncSync(fd);
      } finally {
        fs.closeSync(fd);
      }
    } catch (exc) {
      this.reload(); // a failed write may have left part of a line; take the state from the file again
      throw exc;
    }
    this.seq += tokens.length;
    this.prev = digest(Buffer.from(tokens[tokens.length - 1], "ascii"));
  }

  private reload(): void {
    let lines: string[];
    try {
      lines = readLines(this.receipts);
    } catch {
      return; // the file cannot be read; keep what we knew
    }
    this.seq = lines.length;
    this.prev = lines.length > 0 ? digest(Buffer.from(lines[lines.length - 1], "ascii")) : null;
  }

  /** The last sequence number and the digest of that record: what a checkpoint signs. */
  head(): [number, string | null] {
    return [this.seq, this.prev];
  }

  /** A checkpoint of this log's head, signed by `anchor`, which must not be the key that signs the log. */
  checkpoint(anchor: Signer, o: { session: string; now: number }): string {
    if (anchor.kid === this.signer.kid) throw new RangeError("a checkpoint must be signed by a key the log writer does not hold");
    if (this.seq === 0 || this.prev === null) throw new RangeError("the log is empty");
    return makeCheckpoint(anchor, { session: o.session, seq: this.seq, head: this.prev, now: o.now });
  }
}

/** What one release record is made from (spec 10.4). `code` and `reason` go with a deny. */
export interface ReleaseEntry {
  session: string;
  now: number;
  handle: string;
  data: string | null;
  source: string | null;
  sink: { tool: string | null; site: string | null };
  call: string;
  decision: "allow" | "deny";
  authority: { kind: string; ref?: string | null; digest?: string | null; by?: string | null; channel?: string | null; shown?: string | null };
  code?: string | null;
  reason?: string | null;
  usesLeft?: number | null;
}

/** The signed body of a release record. Refuses anything that does not fit the schema, so a bug cannot put a value in. */
export function releaseBody(e: ReleaseEntry, seq: number, prev: string | null): Record<string, unknown> {
  if (e.decision !== "allow" && e.decision !== "deny") throw new RangeError("decision is allow or deny");
  const authority: Record<string, string> = {};
  for (const [k, v] of Object.entries(e.authority)) if (v != null) authority[k] = v;
  if (!AUTHORITY_KINDS.includes(authority.kind) || !Object.keys(authority).every((k) => ["kind", "ref", "digest", "by", "channel", "shown"].includes(k))) {
    throw new RangeError("authority is {kind, ref?, digest?, by?, channel?, shown?}");
  }
  const body: Record<string, unknown> = {
    opn: "0.1", type: "release", session: e.session, seq, prev, iat: e.now, handle: e.handle, data: e.data ?? null,
    source: e.source ?? null, sink: { tool: e.sink.tool ?? null, site: e.sink.site ?? null }, call: e.call,
    outcome: e.decision === "allow" ? "released" : "refused", decision: e.decision, authority,
  };
  if (e.decision === "deny") {
    if (!e.code || !(CODES as readonly string[]).includes(e.code) || e.code === "not_recorded") {
      throw new RangeError("a recorded denial carries one of the stable codes, except not_recorded");
    }
    body.code = e.code;
    body.reason = e.reason;
  }
  if (e.usesLeft != null) body.uses_left = e.usesLeft;
  return body;
}

/** Sign a checkpoint: the head (the digest of record `seq`) of a log, by a key that is not the log writer's. */
export function makeCheckpoint(signer: Signer, o: { session: string; seq: number; head: string; now: number }): string {
  return signer.sign({ opn: "0.1", type: "checkpoint", session: o.session, seq: o.seq, head: o.head, iat: o.now }, CHECKPOINT_TYP);
}

export interface LogReport {
  receipts: number;
  /** How many of the records are release records. */
  releases: number;
  rechecked: number;
  leaks: number;
  problems: string[];
  /** The digest of the last receipt, to record elsewhere and pass back as `expectLast` later. */
  last: string | null;
  /** The highest sequence number a valid checkpoint vouches for, or null. */
  provenTo: number | null;
  /** "complete": the last record is vouched for. "prefix": the records are valid as far as they go, the end is not proven. */
  status: "complete" | "prefix";
  /** Why the log is not complete: "no_anchor" or "unanchored_tail". */
  reason: "no_anchor" | "unanchored_tail" | null;
}

export interface VerifyOptions {
  /** How many requests were sent, as recorded elsewhere. */
  expectCount?: number | null;
  /** The digest of the last receipt (the x-opn-receipt header the app kept). */
  expectLast?: string | null;
  /** The session id the receipts must belong to, so a log from another session is not taken for this one. */
  expectSession?: string | null;
  /** Checkpoints (compact JWS strings) made by a key the log writer does not hold. */
  anchors?: Iterable<string>;
  /** The public key of whoever made the checkpoints. */
  anchorKey?: KeyObject | null;
}

/**
 * Check every record: signature, chain, payload digest and (with the vault) the egress check again.
 *
 * A chain proves that nothing in the middle was changed, but not that nothing was cut off the end. Two ways to catch
 * that. Pass what you recorded elsewhere: the number of requests sent (`expectCount`) or the digest of the last receipt
 * (`expectLast`, from the x-opn-receipt header the app kept). Or pass checkpoints (`anchors`) made by a key the log
 * writer does not hold (`anchorKey`, its public key): the report then says how far the log is proven complete.
 *
 * Release records (spec 10.4) are checked for their fields, and, given the vault, for any real value in them.
 *
 * Returns counts, a list of problems (an empty list means the log holds up), and `provenTo` (the highest sequence
 * number a valid checkpoint vouches for, or null), `status` ("complete" or "prefix") and `reason` (why not complete).
 * "complete" says nothing about whether the records are valid: read `problems` too.
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
  let egressLines = 0;
  let releases = 0;
  let session0: string | null = null;
  const restorer = vault ? new Restorer(vault) : null;
  for (const [idx, token] of lines.entries()) {
    const i = idx + 1;
    const typ = lineTyp(token);
    let body: Record<string, any>;
    try {
      body = verify(token, publicKey, typ);
    } catch (exc) {
      // a damaged line must never stop the rest of the check
      if (exc instanceof SignatureError) problems.push(`receipt ${i}: ${exc.message}`);
      else problems.push(`receipt ${i}: unreadable (${exc instanceof Error ? exc.name : "Error"})`);
      prev = safeDigest(token);
      egressLines += 1;
      continue;
    }
    if (session0 === null && typeof body.session === "string") session0 = body.session;
    if (o.expectSession != null && body.session !== o.expectSession) problems.push(`receipt ${i}: belongs to another session`);
    if (body.seq !== i) problems.push(`receipt ${i}: sequence number is ${body.seq}`);
    if ((body.prev ?? null) !== prev) problems.push(`receipt ${i}: chain broken (prev does not match receipt ${i - 1})`);
    const pfile = path.join(folder, "payloads", `${String(i).padStart(6, "0")}.bin`);
    if (typ === RELEASE_TYP) {
      releases += 1;
      const bad = releaseProblems(i, body);
      problems.push(...bad);
      if (vault && bad.length === 0) {
        const found = check(vault, canonical(body), restorer);
        leaksTotal += found.length;
        if (found.length > 0) problems.push(`release ${i}: ${found.length} known value(s) found in the record`);
      }
      if (fs.existsSync(pfile)) problems.push(`release ${i}: a release record has a stored payload`);
      prev = safeDigest(token);
      continue;
    }
    egressLines += 1;
    if (body.check?.found) problems.push(`receipt ${i}: was sent with ${body.check.found} known value(s) present`);
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
  if (vault && egressLines > 0 && rechecked === 0) {
    problems.push("no stored payloads to re-check: they were never kept, or they were removed");
  }
  if (o.expectCount != null && o.expectCount !== lines.length) {
    problems.push(`expected ${o.expectCount} receipt(s), found ${lines.length}: the log was cut or added to`);
  }
  if (o.expectLast != null && o.expectLast !== prev) {
    problems.push("the last receipt is not the one you recorded: the log was cut or replaced");
  }
  const proven = provenTo(lines, publicKey, o.anchors ?? [], o.anchorKey ?? null, o.expectSession ?? session0, problems);
  const complete = proven !== null && proven === lines.length;
  return {
    receipts: lines.length, releases, rechecked, leaks: leaksTotal, problems, last: prev, provenTo: proven,
    status: complete ? "complete" : "prefix", reason: complete ? null : proven === null ? "no_anchor" : "unanchored_tail",
  };
}

/**
 * The type a line says it is. Anything that is not a release record is read as an egress receipt, so a damaged or
 * foreign line gets the same errors it always did.
 */
function lineTyp(token: string): string {
  try {
    const header = JSON.parse(b64urlDecode(token.split(".")[0]).toString("utf-8"));
    return header !== null && typeof header === "object" && header.typ === RELEASE_TYP ? RELEASE_TYP : RECEIPT_TYP;
  } catch {
    return RECEIPT_TYP;
  }
}

const isInt = (v: unknown): v is number => typeof v === "number" && Number.isInteger(v);
const isDigest = (v: unknown): boolean => typeof v === "string" && DIGEST.test(v);
const isStr = (v: unknown): v is string => typeof v === "string";

/** Everything wrong with the shape of a release record (spec 10.4), one short line each. */
export function releaseProblems(i: number, body: Record<string, any>): string[] {
  const out: string[] = [];
  const bad = (field: string): void => {
    out.push(`release ${i}: ${field} is not valid`);
  };
  const required = ["opn", "type", "session", "seq", "prev", "iat", "handle", "data", "source", "sink", "call", "outcome", "decision", "authority"];
  const allowed = [...required, "reason", "code", "uses_left"];
  const keys = Object.keys(body);
  if (!required.every((k) => keys.includes(k)) || !keys.every((k) => allowed.includes(k))) bad("the field list");
  if (body.opn !== "0.1" || body.type !== "release") bad("opn or type");
  if (!isStr(body.session)) bad("session");
  if (!isInt(body.seq) || !isInt(body.iat)) bad("seq or iat");
  if (body.prev != null && !isDigest(body.prev)) bad("prev");
  if (!(isStr(body.handle) && new RegExp(`^(?:${HANDLE.source})$`, "u").test(body.handle))) bad("handle");
  if (body.data != null && !(isStr(body.data) && /^[A-Z][A-Z0-9_]{1,31}$/u.test(body.data))) bad("data");
  if (body.source != null && !isStr(body.source)) bad("source");
  const sink = body.sink;
  if (!(sink !== null && typeof sink === "object" && !Array.isArray(sink) && Object.keys(sink).sort().join(",") === "site,tool"
      && Object.values(sink).every((v) => v === null || isStr(v)))) bad("sink");
  if (!isDigest(body.call)) bad("call");
  const pair = `${body.outcome}/${body.decision}`;
  if (pair !== "released/allow" && pair !== "refused/deny") bad("outcome and decision");
  const auth = body.authority;
  if (!(auth !== null && typeof auth === "object" && !Array.isArray(auth) && AUTHORITY_KINDS.includes(auth.kind)
      && Object.keys(auth).every((k) => ["kind", "ref", "digest", "by", "channel", "shown"].includes(k))
      && Object.values(auth).every((v) => isStr(v) && v !== "")
      && ["digest", "shown"].every((k) => !(k in auth) || isDigest(auth[k])))) bad("authority");
  if (body.decision === "deny") {
    if (!(CODES as readonly string[]).includes(body.code) || body.code === "not_recorded") bad("code");
    if (!(isStr(body.reason) && body.reason !== "")) bad("reason");
  } else if ("code" in body || "reason" in body) {
    bad("code or reason on an allow");
  }
  if ("uses_left" in body && !(isInt(body.uses_left) && body.uses_left >= 0)) bad("uses_left");
  return out;
}

/**
 * The highest sequence number a valid checkpoint vouches for. Problems are appended for every checkpoint that does
 * not hold up, in particular one past the end of the log (the end was cut off) and one made by the writer's own key.
 */
function provenTo(lines: string[], publicKey: KeyObject, anchorsIn: Iterable<string>, anchorKey: KeyObject | null,
                  session: string | null, problems: string[]): number | null {
  const anchors = [...anchorsIn];
  if (anchors.length === 0) return null;
  if (anchorKey === null) {
    problems.push("anchors were given without an anchor_key to check them with");
    return null;
  }
  if (keyId(anchorKey) === keyId(publicKey)) {
    problems.push("the anchor key is the key that signs the log: a checkpoint must come from a key the writer does not hold");
    return null;
  }
  let proven: number | null = null;
  for (const [idx, token] of anchors.entries()) {
    const n = idx + 1;
    let body: Record<string, any>;
    try {
      body = verify(token, anchorKey, CHECKPOINT_TYP);
    } catch (exc) {
      if (exc instanceof SignatureError) problems.push(`anchor ${n}: ${exc.message}`);
      else problems.push(`anchor ${n}: unreadable (${exc instanceof Error ? exc.name : "Error"})`);
      continue;
    }
    if (!(Object.keys(body).sort().join(",") === "head,iat,opn,seq,session,type" && body.opn === "0.1" && body.type === "checkpoint"
        && isStr(body.session) && isInt(body.seq) && body.seq >= 1 && isDigest(body.head) && isInt(body.iat))) {
      problems.push(`anchor ${n}: not a checkpoint`);
      continue;
    }
    if (session !== null && body.session !== session) {
      problems.push(`anchor ${n}: belongs to another session`);
      continue;
    }
    const seq = body.seq as number;
    if (seq > lines.length) {
      problems.push(`anchor at seq ${seq}: the log was cut off after seq ${lines.length}`);
    } else if (body.head !== safeDigest(lines[seq - 1])) {
      problems.push(`anchor at seq ${seq}: head does not match receipt ${seq}: the log was changed or replaced`);
    } else {
      proven = proven === null ? seq : Math.max(proven, seq);
    }
  }
  return proven;
}

function safeDigest(token: string): string {
  return digest(Buffer.from(token, "utf-8"));
}
