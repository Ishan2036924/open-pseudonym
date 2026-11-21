// Property-based fuzzing (fast-check) of every surface that reads untrusted input, matching sdk/python/tests/test_fuzz.py:
// detection, mask and restore, streaming restore, handle filling with hostile arguments and sinks, the egress check,
// sensitive references, verifyLog on damaged logs and canonical JSON. Seeded so CI is repeatable; OPN_FUZZ_EXAMPLES
// raises the budget, for example OPN_FUZZ_EXAMPLES=5000 node --test test/fuzz.test.ts.
import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import fc from "fast-check";
import {
  EgressLog, HandleRefused, RefusedData, Session, Signer, Sink, Source, Vault, canonical, srefRegions, verifyLog,
} from "../src/index.ts";
import { canonicalArgs } from "../src/jcs.ts";

const NOW = 1793836800;
const RUNS = Number(process.env.OPN_FUZZ_EXAMPLES ?? "60");
const OPTS = { numRuns: RUNS, seed: 8785 };
const PROFILES = ["strict", "draft_reply", "browse_and_fill", "summarize", "secrets_only"];
const PIECES = [
  "Dana Reyes", "Priya Raman", "Omar Haddad", "dana.reyes@gmail.com", "priya@acme.co.uk", "(617) 555-0142",
  "+44 20 7946 0958", "4242 4242 4242 4242", "4111111111111111", "221 Baker Street, Apt 4", "March 12, 2026",
  "2026-04-02", "https://meet.acme.com/r/9921xq", "Northwind Traders Inc.", "code is 482913", "Password: Tr0ub4dor&3",
  "IBAN DE89 3704 0044 0532 0130 00", "SSN 123-45-6789", "Boise", "Hi Sam,", "José Núñez", "\u{1f600}",
];
const HOSTILE = ["{{OTP_1}}", "⟦", "⟧", "[EMAIL_1]", "@", "...", " ", "\n", "\t", ", ", "."];
const SEPS = [" ", "\n", ", ", ". ", " (", ") ", ": ", "; ", " - ", "\t"];

const noise = fc.string({ unit: "binary", maxLength: 12 });
const texts = fc.array(fc.oneof(fc.constantFrom(...PIECES, ...HOSTILE), noise), { maxLength: 14 }).map((p) => p.join(""));
const anyText = fc.oneof(texts, fc.string({ unit: "binary", maxLength: 200 }));
// real text puts a space or a mark between two values (see the Python file for why glued values are left out)
const words = fc.string({ unit: "grapheme", maxLength: 10 }).filter((w) => !/[⟦⟧{}[\]]/.test(w));
const separated = fc.array(fc.tuple(fc.oneof(fc.constantFrom(...PIECES), words), fc.constantFrom(...SEPS)), { maxLength: 10 })
  .map((parts) => parts.map(([p, s]) => p + s).join(""));
const jsonValue = fc.jsonValue({ maxDepth: 3 });
const hosts = fc.oneof(
  fc.constantFrom("acme.com", "https://acme.com/2fa", "login.acme.com", "github.io", "", ".", "..", "acme.com.", "[::1]:80",
    "x@acme.com", "https://u:p@acme.com:8443/x?y#z"),
  fc.string({ maxLength: 40 }),
);

function session(profile = "strict", extra: Record<string, unknown> = {}) {
  return new Session(profile, { vault: new Vault(Buffer.alloc(32, 0), NOW), clock: () => NOW, ...extra });
}

function maskOrRefuse(s: Session, text: string, source?: Source) {
  try {
    return s.mask(text, source);
  } catch (e) {
    if (e instanceof RefusedData) return null;
    throw e;
  }
}

test("detect spans lie inside the text and mask never crashes", () => {
  fc.assert(fc.property(anyText, fc.constantFrom(...PROFILES), (text, profile) => {
    const s = session(profile);
    for (const sp of s.detect(text)) {
      assert.ok(0 <= sp.start && sp.start < sp.end && sp.end <= text.length);
      assert.equal(text.slice(sp.start, sp.end), sp.text);
    }
    maskOrRefuse(s, text, new Source({ sender: "no-reply@acme.com" }));
  }), OPTS);
});

test("mask then restore gives the original", () => {
  fc.assert(fc.property(separated, fc.constantFrom("strict", "draft_reply", "browse_and_fill"), (text, profile) => {
    const s = session(profile);
    const m = maskOrRefuse(s, text, new Source({ sender: "no-reply@acme.com" }));
    fc.pre(m !== null);
    assert.equal(s.restore(m!.text, true), text);
  }), OPTS);
});

test("streaming restore matches the whole restore however the text is cut", () => {
  fc.assert(fc.property(separated, fc.array(fc.integer({ min: 1, max: 12 }), { minLength: 1, maxLength: 40 }), (text, cuts) => {
    const s = session("strict");
    const m = maskOrRefuse(s, text);
    fc.pre(m !== null);
    const masked = m!.text + " " + m!.text;
    const st = s.stream();
    const out: string[] = [];
    for (let i = 0, k = 0; i < masked.length; k++) {
      const n = cuts[k % cuts.length];
      out.push(st.feed(masked.slice(i, i + n)));
      i += n;
    }
    out.push(st.flush());
    assert.equal(out.join(""), s.restore(masked));
  }), OPTS);
});

test("restore and stream never crash on model output", () => {
  const s = session("draft_reply");
  s.mask("From: Dana Reyes <dana.reyes@gmail.com>, (617) 555-0142, code 482913", new Source({ sender: "a@acme.com" }));
  fc.assert(fc.property(anyText, (text) => {
    s.restore(text);
    s.restore(text, true);
    s.unknownStandIns(text);
    const st = s.stream();
    st.feed(text);
    st.flush();
  }), OPTS);
});

test("resolveArgs refuses only with HandleRefused", () => {
  const args = fc.oneof(jsonValue, anyText, fc.constantFrom('{"t": "{{OTP_1}}"', '["{{OTP_1}}"]', "{{OTP_1}}", '{"t": "{{OTP_9}}"}',
    '{"a": "\\ud800 {{OTP_1}}"}'));
  const answers = fc.constantFrom(undefined, true, false, "yes", { allowed: true }, 1, []);
  fc.assert(fc.property(args, fc.option(anyText), fc.option(hosts), answers, (a, tool, site, answer) => {
    const s = session("browse_and_fill", answer === undefined ? {} : { approve: () => answer });
    s.mask("Your Acme verification code is 482913. It expires in 10 minutes.", new Source({ sender: "no-reply@acme.com" }));
    const input = a !== null && typeof a === "object" ? { x: a, code: "{{OTP_1}}" } : a;
    try {
      s.resolveArgs(input, new Sink({ tool, site }));
    } catch (e) {
      if (e instanceof HandleRefused) return assert.ok(e.code);
      // a bad approval answer is the caller's bug, and says so
      assert.ok(e instanceof TypeError && typeof answer !== "boolean" && answer !== undefined, String(e));
    }
  }), OPTS);
});

test("the egress check never crashes and finds real values", () => {
  const s = session("strict");
  s.mask("From: Dana Reyes <dana.reyes@gmail.com>, (617) 555-0142");
  fc.assert(fc.property(fc.oneof(anyText, fc.uint8Array({ maxLength: 200 }), jsonValue.map((v) => JSON.stringify(v))), (payload) => {
    s.checkEgress(payload);
    if (typeof payload === "string") assert.ok(s.checkEgress(payload + " dana.reyes@gmail.com").length > 0);
  }), OPTS);
});

test("sensitive-reference regions are sorted and inside the text", () => {
  fc.assert(fc.property(anyText, (text) => {
    let last = 0;
    for (const [a, b] of srefRegions(text)) {
      assert.ok(last <= a && a < b && b <= text.length);
      last = b;
    }
  }), OPTS);
});

test("verifyLog reports damage and never throws", () => {
  const ops = fc.oneof(
    fc.record({ op: fc.constant("flip"), at: fc.nat(), by: fc.integer({ min: 1, max: 255 }) }),
    fc.record({ op: fc.constant("cut"), at: fc.nat() }),
    fc.record({ op: fc.constant("insert"), at: fc.nat(), bytes: fc.uint8Array({ minLength: 1, maxLength: 20 }) }),
    fc.record({ op: fc.constantFrom("drop_line", "swap", "dup", "payload"), at: fc.nat() }),
  );
  const signer = Signer.fromSeed(Buffer.from(Array.from({ length: 32 }, (_, i) => i)));
  fc.assert(fc.property(ops, (d) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "opn-fuzz-"));
    try {
      const s = session("strict");
      const log = new EgressLog(dir, signer);
      for (const t of ["Dana Reyes wrote", "and (617) 555-0142", "fine"]) {
        s.recordEgress(log, JSON.stringify({ messages: [{ content: s.mask(t).text }] }), "api.example.com");
      }
      const good = verifyLog(dir, signer.publicKey, s.vault);
      assert.deepEqual(good.problems, []);
      const file = path.join(dir, "receipts.jsonl");
      const before = fs.readFileSync(file);
      let raw = Buffer.from(before);
      if (d.op === "flip") raw[d.at % raw.length] ^= (d as { by: number }).by;
      else if (d.op === "cut") raw = raw.subarray(0, d.at % raw.length);
      else if (d.op === "insert") { const i = d.at % (raw.length + 1); raw = Buffer.concat([raw.subarray(0, i), (d as { bytes: Uint8Array }).bytes, raw.subarray(i)]); }
      else if (d.op === "payload") fs.appendFileSync(path.join(dir, "payloads", "000002.bin"), "x");
      else {
        const lines = before.toString("utf8").split("\n").slice(0, -1);
        if (d.op === "drop_line") lines.splice(d.at % lines.length, 1);
        else if (d.op === "swap") [lines[0], lines[1]] = [lines[1], lines[0]];
        else lines.splice(1, 0, lines[1]);
        raw = Buffer.from(lines.join("\n") + "\n");
      }
      fs.writeFileSync(file, raw);
      const report = verifyLog(dir, signer.publicKey, s.vault, { expectCount: 3, expectLast: good.last });
      // read the way verifyLog reads: Python's str.splitlines() line breaks
      const records = (b: Buffer) => b.toString("utf8").split(/\r\n|[\n\v\f\r\x1c-\x1e\x85\u2028\u2029]/).filter((l) => l.trim() !== "");
      if (d.op === "payload" || JSON.stringify(records(raw)) !== JSON.stringify(records(before))) {
        assert.ok(report.problems.length > 0, `${d.op} went unnoticed`);
      }
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }), OPTS);
});

test("canonical JSON is idempotent", () => {
  fc.assert(fc.property(jsonValue, (v) => {
    let once: string;
    try {
      once = canonicalArgs(v).toString("utf8");
    } catch (e) {
      assert.ok(e instanceof TypeError, String(e)); // a lone surrogate, or a number JSON cannot hold
      return;
    }
    assert.equal(canonicalArgs(JSON.parse(once)).toString("utf8"), once);
  }), OPTS);
  const safe = fc.letrec((tie) => ({
    v: fc.oneof(fc.constant(null), fc.boolean(), fc.maxSafeInteger(), fc.string({ maxLength: 20 }),
      fc.array(tie("v"), { maxLength: 4 }), fc.dictionary(fc.string({ maxLength: 8 }), tie("v"), { maxKeys: 4 })),
  })).v;
  fc.assert(fc.property(safe, (v) => {
    const once = canonical(v).toString("utf8");
    assert.equal(canonical(JSON.parse(once)).toString("utf8"), once);
  }), OPTS);
});

test("canonical JSON refuses what is not JSON instead of writing something else (found by fuzzing)", () => {
  // [1,,2] came out as "[1,,2]" (not JSON) and a Date, Map, typed array or boxed string as "{}" or index keys, so a
  // tool call holding one got the digest of other arguments; Python refuses them, and now so does this SDK
  for (const v of [[1, , 2], new Date(0), new Map([[1, 2]]), new Uint8Array([1, 2]), new String("x"), { a: [new Set()] }]) {
    assert.throws(() => canonicalArgs(v), TypeError);
    assert.throws(() => canonical(v), TypeError);
  }
  const s = session("browse_and_fill");
  s.mask("Your Acme verification code is 482913.", new Source({ sender: "no-reply@acme.com" }));
  assert.throws(() => s.resolveArgs({ t: "{{OTP_1}}", when: new Date(0) }, new Sink({ tool: "type", site: "acme.com" })),
    (e: unknown) => e instanceof HandleRefused && e.code === "malformed");
  fc.assert(fc.property(fc.anything({ withDate: true, withMap: true, withSet: true, withTypedArray: true, withSparseArray: true,
    withBoxedValues: true, withNullPrototype: true }), (v) => {
    let out: string;
    try {
      out = canonicalArgs(v).toString("utf8");
    } catch (e) {
      return assert.ok(e instanceof TypeError, String(e));
    }
    assert.equal(canonicalArgs(JSON.parse(out)).toString("utf8"), out); // whatever is accepted is real JSON
  }), OPTS);
});
