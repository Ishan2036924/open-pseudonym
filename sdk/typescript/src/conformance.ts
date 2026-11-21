// Runs the shared vectors against this SDK: node src/conformance.ts path/to/vectors
//
// Exit code 0 means every vector passed. Each failure prints the file, the case and what differed.

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { pathToFileURL } from "node:url";
import { isDeepStrictEqual } from "node:util";
import * as checks from "./checks.ts";
import { Drbg } from "./drbg.ts";
import { EgressLog, makeCheckpoint, releaseBody, verifyLog, type ReleaseEntry } from "./egress.ts";
import { FF1 } from "./fpe.ts";
import { HandleRefused, Sink, Source, type Approval } from "./handles.ts";
import { canonical, digest } from "./jcs.ts";
import { Signer, verify } from "./jws.ts";
import { PolicyError, loadProfile } from "./policy.ts";
import { Session } from "./session.ts";
import { Vault } from "./vault.ts";

const ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyz";

const hex = (s: string): Buffer => Buffer.from(s, "hex");

export interface Outcome {
  passed: number;
  failed: string[];
}

class Runner {
  readonly folder: string;
  passed = 0;
  failed: string[] = [];

  constructor(folder: string) {
    this.folder = folder;
  }

  ok(cond: boolean, where: string, detail = ""): void {
    if (cond) this.passed += 1;
    else this.failed.push(detail ? `${where}: ${detail}` : where);
  }

  load(name: string): any {
    return JSON.parse(fs.readFileSync(path.join(this.folder, `${name}.json`), "utf-8"));
  }

  run(): Outcome {
    this.checks(this.load("checks"));
    this.drbg(this.load("drbg"));
    this.ff1(this.load("ff1"));
    this.detect(this.load("detect"));
    this.policy(this.load("policy"));
    this.scenarios(this.load("scenarios"));
    this.receipts(this.load("receipts"));
    this.releases(this.load("releases"));
    this.checkpoints(this.load("checkpoints"));
    return { passed: this.passed, failed: this.failed };
  }

  checks(doc: any): void {
    const fns: Record<string, (v: string) => boolean> = {
      card: checks.cardOk, iban: checks.ibanOk, aba: checks.abaOk, ssn: checks.ssnOk, phone: checks.phoneOk,
      name: checks.nameOk,
    };
    for (const c of doc.cases) this.ok(fns[c.check](c.value) === c.ok, `checks ${c.check} ${JSON.stringify(c.value)}`);
  }

  drbg(doc: any): void {
    const seed = hex(doc.seed);
    const fb = doc.first_block;
    this.ok(new Drbg(seed).block(fb.label).toString("hex") === fb.hex, "drbg first block");
    this.ok(new Drbg(seed).derive(doc.derive.purpose).toString("hex") === doc.derive.hex, "drbg derive");
    const d = new Drbg(seed);
    doc.draws.forEach((draw: any, i: number) => {
      const got = d.below(draw.label, draw.n);
      this.ok(got === draw.value, `drbg draw ${i}`, `got ${got}, want ${draw.value}`);
    });
  }

  ff1(doc: any): void {
    doc.cases.forEach((c: any, i: number) => {
      const f = new FF1(hex(c.key), c.radix);
      const pt = [...c.pt].map((ch: string) => ALPHABET.indexOf(ch));
      const ct = f.encrypt(pt, hex(c.tweak)).map((x) => ALPHABET[x]).join("");
      this.ok(ct === c.ct, `ff1 case ${i}`, `got ${ct}`);
      const back = f.decrypt([...ct].map((ch) => ALPHABET.indexOf(ch)), hex(c.tweak)).map((x) => ALPHABET[x]).join("");
      this.ok(back === c.pt, `ff1 case ${i} decrypt`);
    });
  }

  detect(doc: any): void {
    doc.cases.forEach((c: any, i: number) => {
      const s = new Session(c.profile, { vault: new Vault(Buffer.alloc(32)), clock: () => c.now });
      const got = s.detect(c.text).map((sp) => [sp.type, sp.text]);
      this.ok(isDeepStrictEqual(got, c.spans), `detect case ${i}`, `got ${JSON.stringify(got)}`);
    });
  }

  policy(doc: any): void {
    doc.cases.forEach((c: any, i: number) => {
      const where = `policy case ${i} (${c.op})`;
      const matches = (p: { ruleFor(t: string): { action: string } }) =>
        Object.entries(c.expect).every(([k, v]) => p.ruleFor(k).action === v);
      if (c.op === "tighten") {
        this.ok(matches(loadProfile(c.a).tighten(loadProfile(c.b))), where);
      } else if (c.op === "with_rules") {
        try {
          const p = loadProfile(c.base).withRules(c.rules);
          this.ok("expect" in c && matches(p), where);
        } catch (exc) {
          if (!(exc instanceof PolicyError)) throw exc;
          this.ok(c.error === exc.message, where, exc.message);
        }
      } else if (c.op === "digest") {
        this.ok(loadProfile(c.profile).digest === c.expect, where);
      }
    });
  }

  scenarios(doc: any): void {
    for (const sc of doc.scenarios) {
      const s = new Session(sc.profile, {
        vault: new Vault(hex(sc.seed), sc.now), clock: () => sc.now, known: sc.known,
      });
      sc.steps.forEach((st: any, j: number) => {
        const where = `scenario ${JSON.stringify(sc.name)} step ${j} (${st.op})`;
        const got = step(s, st);
        this.ok(isDeepStrictEqual(got, st.expect), where, `got ${JSON.stringify(got).slice(0, 300)}`);
      });
    }
  }

  releases(doc: any): void {
    this.ok(signer("writer").kid === doc.kid, "releases kid");
    for (const c of doc.cases) {
      const where = `release case ${JSON.stringify(c.name)}`;
      const got = withTempDir((dir) => runReleaseCase(c, dir));
      this.ok(isDeepStrictEqual(got.results, c.results), where + " results", JSON.stringify(got.results).slice(0, 300));
      this.ok(isDeepStrictEqual(got.records, c.records), where + " records", JSON.stringify(got.records).slice(0, 300));
      this.ok(isDeepStrictEqual(got.tokens, c.tokens), where + " tokens");
      this.ok(got.problems.length === 0, where + " verify", got.problems.join("; "));
      const text = got.records.map((r) => canonical(r).toString("utf-8")).join("\n");
      this.ok(!c.never_in_records.some((n: string) => text.includes(n)), where + " holds no value or hash");
    }
    for (const c of doc.shapes) {
      const got = withTempDir((dir) => runShapeCase(c, dir));
      this.ok(isDeepStrictEqual(got, c.problems), `release shape ${JSON.stringify(c.name)}`, JSON.stringify(got).slice(0, 300));
    }
  }

  checkpoints(doc: any): void {
    for (const c of doc.cases) {
      const got = withTempDir((dir) => runCheckpointCase(doc, c, dir));
      const where = `checkpoint case ${JSON.stringify(c.name)}`;
      this.ok(isDeepStrictEqual(got.full, doc.tokens), where + " log tokens");
      this.ok(isDeepStrictEqual(got.tokens, c.anchor_tokens), where + " anchor tokens");
      this.ok(isDeepStrictEqual(got.result, c.expect), where, JSON.stringify(got.result).slice(0, 300));
    }
  }

  receipts(doc: any): void {
    const signer = Signer.fromSeed(hex(doc.private_key_seed));
    this.ok(signer.kid === doc.kid, "receipts kid");
    this.ok(canonical(doc.body).toString("utf-8") === doc.canonical_body, "receipts canonical body");
    this.ok(signer.sign(doc.body, "opn-egress+jws") === doc.token, "receipts token");
    this.ok(isDeepStrictEqual(verify(doc.token, signer.publicKey, "opn-egress+jws"), doc.body), "receipts verify");
    this.ok(digest(Buffer.from("hello")) === doc.payload_digest_of_hello, "receipts digest");
  }
}

const SEEDS: Record<string, Buffer> = {
  writer: Buffer.from(Array.from({ length: 32 }, (_, i) => i)),
  anchor: Buffer.from(Array.from({ length: 32 }, (_, i) => 32 + i)),
  other: Buffer.alloc(32, 9),
};
const signer = (name: string): Signer => Signer.fromSeed(SEEDS[name]);

function withTempDir<T>(fn: (dir: string) => T): T {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "opn-vec-"));
  try {
    return fn(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

const readLines = (dir: string): string[] =>
  fs.readFileSync(path.join(dir, "receipts.jsonl"), "utf-8").split("\n").filter((l) => l.trim() !== "");

/** Plays one release case through the SDK; the twin of run_release_case in the Python runner. */
function runReleaseCase(c: any, dir: string) {
  let now = c.now as number;
  const spec = c.approve;
  const approve = spec === null ? undefined : () => (typeof spec === "boolean" ? spec : (spec as Approval));
  const writer = signer("writer");
  const s = new Session(c.profile, {
    vault: new Vault(hex(c.seed), c.now), clock: () => now, approve, sessionId: "s1",
    releaseLog: new EgressLog(dir, writer, false),
  });
  if (c.mask) s.mask(c.mask.text, c.mask.source ? new Source(c.mask.source) : null);
  const results: unknown[] = [];
  for (const st of c.steps) {
    if (st.at !== undefined) now = st.at;
    if (st.op === "break_log") {
      fs.mkdirSync(path.join(dir, "receipts.jsonl")); // appending to a folder fails
      continue;
    }
    if (st.op === "fix_log") {
      fs.rmdirSync(path.join(dir, "receipts.jsonl"));
      continue;
    }
    try {
      results.push({ args: s.resolveArgs(st.args, new Sink(st.sink)).args });
    } catch (exc) {
      if (!(exc instanceof HandleRefused)) throw exc;
      results.push({ refused: exc.reason, code: exc.code });
    }
  }
  const tokens = readLines(dir);
  const records = tokens.map((t) => verify(t, writer.publicKey, "opn-release+jws"));
  return { results, records, tokens, problems: verifyLog(dir, writer.publicKey, s.vault).problems };
}

/** Signs a release record changed the way `c` says and returns what verifyLog reports about it. */
function runShapeCase(c: any, dir: string): string[] {
  const writer = signer("writer");
  const body = releaseBody(c.entry as ReleaseEntry, 1, null);
  for (const [k, v] of Object.entries(c.set ?? {})) body[k] = v;
  for (const k of c.delete ?? []) delete body[k];
  fs.writeFileSync(path.join(dir, "receipts.jsonl"), writer.sign(body, "opn-release+jws") + "\n");
  let vault: Vault | null = null;
  if (c.mask) {
    const s = new Session(c.profile, { vault: new Vault(hex(c.seed), c.now), clock: () => c.now });
    s.mask(c.mask);
    vault = s.vault;
  }
  return verifyLog(dir, writer.publicKey, vault).problems;
}

/** Writes the log in `doc`, cuts it to `keep` records, signs the case's checkpoints and verifies the log. */
function runCheckpointCase(doc: any, c: any, dir: string) {
  const writer = signer("writer");
  const log = new EgressLog(dir, writer, false);
  for (const e of doc.entries) log.recordRelease(e as ReleaseEntry);
  const full = readLines(dir);
  fs.writeFileSync(path.join(dir, "receipts.jsonl"), full.slice(0, c.keep).map((l) => l + "\n").join(""));
  const tokens = c.anchors.map((a: any) => {
    const head = a.head === "other" ? digest(Buffer.from("another log")) : digest(Buffer.from(full[a.seq - 1], "ascii"));
    return makeCheckpoint(signer(a.signer ?? "anchor"), { session: a.session ?? "s1", seq: a.seq, head, now: doc.now });
  });
  const key = "anchor_key" in c ? c.anchor_key : "anchor";
  const r = verifyLog(dir, writer.publicKey, null, {
    anchors: tokens, anchorKey: key ? signer(key).publicKey : null, expectCount: c.expect_count ?? null,
  });
  return {
    full, tokens,
    result: { receipts: r.receipts, problems: r.problems, proven_to: r.provenTo, status: r.status, reason: r.reason },
  };
}

function step(s: Session, st: any): unknown {
  switch (st.op) {
    case "mask": {
      const m = s.mask(st.text, st.source ? new Source(st.source) : null);
      return { text: m.text, notes: m.notes };
    }
    case "restore":
      return s.restore(st.text, st.reveal ?? false);
    case "stream": {
      const sr = s.stream(st.reveal ?? false);
      // the vectors count characters, not UTF-16 units, so cut the text the same way
      const text = [...(st.text as string)];
      const out: string[] = [];
      let i = 0;
      for (const n of st.chunks as number[]) {
        out.push(sr.feed(text.slice(i, i + n).join("")));
        i += n;
      }
      out.push(sr.feed(text.slice(i).join("")));
      out.push(sr.flush());
      return out.join("");
    }
    case "resolve":
      try {
        return { args: s.resolveArgs(st.args, new Sink(st.sink)).args };
      } catch (exc) {
        if (exc instanceof HandleRefused) return { refused: exc.reason };
        throw exc;
      }
    case "resolve_report":
      return { report: s.resolveArgs(st.args, new Sink(st.sink)).report };
    case "egress":
      return [...new Set(s.checkEgress(st.payload).map((lk) => lk.type))].sort();
    case "mask_messages": {
      const [messages, notes] = s.maskMessages(st.messages);
      return { messages, notes };
    }
    default:
      throw new Error(`unknown step ${st.op}`);
  }
}

/** Run every vector in `folder` and report what passed and what did not. */
export function run(folder: string): Outcome {
  return new Runner(folder).run();
}

export function main(argv: string[]): number {
  const { passed, failed } = run(argv[0] ?? "vectors");
  for (const f of failed) console.log("FAIL", f);
  console.log(`${passed} passed, ${failed.length} failed`);
  return failed.length > 0 ? 1 : 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exit(main(process.argv.slice(2)));
}
