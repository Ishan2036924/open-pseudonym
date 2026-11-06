// Runs the shared vectors against this SDK: node src/conformance.ts path/to/vectors
//
// Exit code 0 means every vector passed. Each failure prints the file, the case and what differed.

import * as fs from "node:fs";
import * as path from "node:path";
import { pathToFileURL } from "node:url";
import { isDeepStrictEqual } from "node:util";
import * as checks from "./checks.ts";
import { Drbg } from "./drbg.ts";
import { FF1 } from "./fpe.ts";
import { HandleRefused, Sink, Source } from "./handles.ts";
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

  receipts(doc: any): void {
    const signer = Signer.fromSeed(hex(doc.private_key_seed));
    this.ok(signer.kid === doc.kid, "receipts kid");
    this.ok(canonical(doc.body).toString("utf-8") === doc.canonical_body, "receipts canonical body");
    this.ok(signer.sign(doc.body, "opn-egress+jws") === doc.token, "receipts token");
    this.ok(isDeepStrictEqual(verify(doc.token, signer.publicKey, "opn-egress+jws"), doc.body), "receipts verify");
    this.ok(digest(Buffer.from("hello")) === doc.payload_digest_of_hello, "receipts digest");
  }
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
