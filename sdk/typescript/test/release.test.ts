// Release records (spec 10.4), checkpoints (spec 11.3) and the sensitive-reference boundary (spec 10.5).
// Each test here is meant to fail if the check it names is taken out; see the list in CHANGELOG.md.

import { mock, test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import * as fs from "node:fs";
import fsLive from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import * as os from "node:os";
import * as path from "node:path";
import {
  EgressLog, HandleRefused, Policy, Session, Signer, Sink, Source, Vault, canonical, digest, loadProfile, makeCheckpoint,
  srefRegions, verify, verifyLog, type Approval, type SessionOptions,
} from "../src/index.ts";
import { canonicalArgs } from "../src/jcs.ts";
import { releaseBody } from "../src/egress.ts";

const NOW = 1793836800;
const OTP_MAIL = "Your Acme verification code is 482913. It expires in 10 minutes.";
const WRITER = Signer.fromSeed(Buffer.from(Array.from({ length: 32 }, (_, i) => i)));
const ANCHOR = Signer.fromSeed(Buffer.from(Array.from({ length: 32 }, (_, i) => 32 + i)));
const ACME = new Sink({ tool: "type", site: "https://acme.com/login" });
const SREF_BARE = "sref:contact:42424242424242424242424242"; // a ULID made of digits that look like a card
const ULID = "01JCK7KF9X4Y3M4N6Q6YB2D8P0";
const SREF_BRACKET = "⟦sref:account:01JCK7KF9X4Y3M4N6Q6YB2D8P0⟧";

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), "opn-rel-"));

function records(folder: string): Record<string, any>[] {
  return fs.readFileSync(path.join(folder, "receipts.jsonl"), "utf-8").split("\n").filter((l) => l.trim() !== "").map((line) => {
    const typ = JSON.parse(Buffer.from(line.split(".")[0], "base64url").toString()).typ;
    return verify(line, WRITER.publicKey, typ);
  });
}

function make(profile: string, o: SessionOptions = {}) {
  return new Session(profile, { vault: new Vault(Buffer.alloc(32), NOW), clock: () => NOW, ...o });
}

function withLog(folder: string, o: SessionOptions = {}, profile = "browse_and_fill") {
  const log = new EgressLog(folder, WRITER, false);
  const s = make(profile, { releaseLog: log, ...o });
  s.mask(OTP_MAIL, new Source({ sender: "no-reply@acme.com" }));
  return { s, log };
}

function refused(fn: () => unknown): HandleRefused {
  try {
    fn();
  } catch (e) {
    assert.ok(e instanceof HandleRefused, String(e));
    return e;
  }
  throw new assert.AssertionError({ message: "expected a refusal" });
}

// Stable codes

test("refusals carry stable codes and keep their text", () => {
  const s = make("browse_and_fill");
  s.mask(OTP_MAIL, new Source({ sender: "no-reply@acme.com" }));
  s.vault.entries[0].meta.tools = ["type"];
  let e = refused(() => s.resolveArgs({ t: "{{OTP_9}}" }, ACME));
  assert.deepEqual([e.code, e.reason], ["unknown_handle", "unknown handle"]);
  e = refused(() => s.resolveArgs({ t: "{{OTP_1}}" }, new Sink({ tool: "type", site: "https://evil.example" })));
  assert.deepEqual([e.code, e.reason], ["wrong_site", "bound to a different site"]);
  e = refused(() => s.resolveArgs({ t: "{{OTP_1}}" }, new Sink({ tool: "click", site: "https://acme.com" })));
  assert.deepEqual([e.code, e.reason], ["wrong_tool", "not allowed for this tool"]);
  assert.ok(e.message.endsWith("not allowed for this tool"));
  s.resolveArgs({ t: "{{OTP_1}}" }, ACME);
  e = refused(() => s.resolveArgs({ t: "{{OTP_1}}" }, ACME));
  assert.deepEqual([e.code, e.reason], ["used_up", "already used"]);
});

test("expired, unbound and approval codes", () => {
  let now = NOW;
  const s2 = new Session("browse_and_fill", { vault: new Vault(Buffer.alloc(32), NOW), clock: () => now });
  s2.mask(OTP_MAIL, new Source({ sender: "no-reply@acme.com" }));
  now += 601;
  let e = refused(() => s2.resolveArgs({ t: "{{OTP_1}}" }, ACME));
  assert.deepEqual([e.code, e.reason], ["expired", "expired"]);
  const s3 = make("browse_and_fill");
  s3.mask(OTP_MAIL);
  e = refused(() => s3.resolveArgs({ t: "{{OTP_1}}" }, ACME));
  assert.deepEqual([e.code, e.reason], ["unbound", "not bound to a site or tool"]);
  const s4 = make("browse_and_fill");
  s4.mask("card 4242 4242 4242 4242", new Source({ site: "https://shop.example" }));
  e = refused(() => s4.resolveArgs({ t: "{{CARD_1}}" }, new Sink({ tool: "type", site: "https://shop.example" })));
  assert.deepEqual([e.code, e.reason], ["needs_approval", "needs the person's approval"]);
  const s5 = make("browse_and_fill", { approve: () => false });
  s5.mask(OTP_MAIL, new Source({ sender: "no-reply@acme.com" }));
  e = refused(() => s5.resolveArgs({ t: "{{OTP_1}}" }, ACME));
  assert.deepEqual([e.code, e.reason], ["not_approved", "not approved"]);
});

// Release records

test("allowed by binding is recorded before it is filled", () => {
  const dir = tmp();
  const { s } = withLog(dir);
  const r = s.resolveArgs({ selector: "#otp", text: "{{OTP_1}}" }, ACME);
  assert.equal(r.args.text, "482913");
  const [rec] = records(dir);
  assert.deepEqual(rec, {
    opn: "0.1", type: "release", session: s.id, seq: 1, prev: null, iat: NOW, handle: "{{OTP_1}}", data: "OTP",
    source: "acme.com", sink: { tool: "type", site: "acme.com" },
    call: digest(canonical({ selector: "#otp", text: "{{OTP_1}}" })), outcome: "released", decision: "allow",
    authority: { kind: "binding", rule: "/rules/OTP", policy: s.policy.digest }, uses_left: 0,
  });
  assert.deepEqual(verifyLog(dir, WRITER.publicKey, s.vault).problems, []);
});

test("allowed by a person records who and what they saw", () => {
  const dir = tmp();
  const { s } = withLog(dir, { approve: (): Approval => ({ allowed: true, by: "mia", channel: "app" }) });
  s.resolveArgs({ text: "{{OTP_1}}" }, ACME);
  const [rec] = records(dir);
  const entry = s.vault.entries[0];
  const plain = { handle: "{{OTP_1}}", description: entry.meta.description, tool: "type", site: "acme.com" };
  const shown = digest(canonical({ nonce: entry.meta.nonce, ...plain }));
  assert.deepEqual(rec.authority, { kind: "person", by: "mia", channel: "app", shown });
  // a hiding commitment: without the vault's nonce the digest cannot be matched, whatever the description holds
  assert.notEqual(rec.authority.shown, digest(canonical(plain)));
  assert.ok(!fs.readFileSync(path.join(dir, "receipts.jsonl"), "utf-8").includes(entry.meta.nonce));
});

test("shown cannot be brute-forced from a card description", () => {
  const dir = tmp();
  const s = make("browse_and_fill", { releaseLog: new EgressLog(dir, WRITER, false), approve: () => ({ allowed: true, by: "mia" }) });
  s.mask("Pay with card 4242 4242 4242 4242 now.", new Source({ site: "https://shop.example" }));
  s.resolveArgs({ card: "{{CARD_1}}" }, new Sink({ tool: "type", site: "https://shop.example/pay" }));
  const shown = records(dir)[0].authority.shown;
  for (const last4 of ["4242", "1111", "0000"]) { // an attacker who tries every brand and last four, but has no nonce
    const guess = digest(canonical({ handle: "{{CARD_1}}", description: `a Visa card ending ${last4}`, tool: "type", site: "shop.example" }));
    assert.notEqual(guess, shown);
  }
  assert.deepEqual(verifyLog(dir, WRITER.publicKey, s.vault).problems, []); // the vault can recompute it
});

test("a plain yes still works and an OAC consent is recorded", () => {
  const dir = tmp();
  const { s } = withLog(dir, { approve: () => true });
  s.resolveArgs({ text: "{{OTP_1}}" }, ACME);
  assert.equal(records(dir)[0].authority.kind, "person");
  assert.deepEqual(Object.keys(records(dir)[0].authority).sort(), ["kind", "shown"]);
  const consent = digest(Buffer.from("the consent token"));
  const dir2 = tmp();
  const { s: s2 } = withLog(dir2, { approve: () => ({ allowed: true, ref: "jti-123", digest: consent }) });
  s2.resolveArgs({ text: "{{OTP_1}}" }, ACME);
  const auth = records(dir2)[0].authority;
  assert.deepEqual([auth.kind, auth.ref, auth.digest], ["consent", "jti-123", consent]);
});

test("a bad approval answer fills nothing", () => {
  const dir = tmp();
  const { s } = withLog(dir, { approve: (() => "yes") as any });
  assert.throws(() => s.resolveArgs({ text: "{{OTP_1}}" }, ACME), TypeError);
  const dir2 = tmp();
  const { s: s2 } = withLog(dir2, { approve: () => ({ allowed: true, digest: "not a digest" }) });
  assert.throws(() => s2.resolveArgs({ text: "{{OTP_1}}" }, ACME), RangeError);
  assert.ok(!fs.existsSync(path.join(dir, "receipts.jsonl")) && !fs.existsSync(path.join(dir2, "receipts.jsonl")));
});

test("denials are recorded with their code", () => {
  const dir = tmp();
  const { s } = withLog(dir);
  refused(() => s.resolveArgs({ text: "{{OTP_1}}" }, new Sink({ tool: "type", site: "https://evil.example" })));
  s.resolveArgs({ text: "{{OTP_1}}" }, ACME);
  refused(() => s.resolveArgs({ text: "{{OTP_1}}" }, ACME));
  const got = records(dir).map((r) => [r.decision, r.code ?? null, r.outcome, r.authority.kind]);
  assert.deepEqual(got, [["deny", "wrong_site", "refused", "binding"], ["allow", null, "released", "binding"], ["deny", "used_up", "refused", "binding"]]);
  assert.equal(records(dir)[0].reason, "bound to a different site");
});

test("a refused approval and a missing approver are recorded", () => {
  const dir = tmp();
  const { s } = withLog(dir, { approve: () => ({ allowed: false, by: "mia" }) });
  refused(() => s.resolveArgs({ text: "{{OTP_1}}" }, ACME));
  const rec = records(dir)[0];
  assert.deepEqual([rec.code, rec.authority.kind, rec.authority.by], ["not_approved", "person", "mia"]);
  assert.ok(rec.authority.shown.startsWith("sha-256:"));
  const dir2 = tmp();
  const s2 = make("browse_and_fill", { releaseLog: new EgressLog(dir2, WRITER, false) });
  s2.mask("card 4242 4242 4242 4242", new Source({ site: "https://shop.example" }));
  refused(() => s2.resolveArgs({ t: "{{CARD_1}}" }, new Sink({ tool: "type", site: "https://shop.example" })));
  const rec2 = records(dir2)[0];
  assert.deepEqual([rec2.code, rec2.authority], ["needs_approval", { kind: "policy", rule: "/rules/CARD", policy: s2.policy.digest }]);
});

test("an unknown handle is a recorded denial with no data", () => {
  const dir = tmp();
  const { s } = withLog(dir);
  refused(() => s.resolveArgs({ t: "{{OTP_9}}" }, ACME));
  const rec = records(dir)[0];
  assert.deepEqual([rec.code, rec.data, rec.source, "uses_left" in rec], ["unknown_handle", null, null, false]);
});

test("audit comes first and a failed write fills nothing", () => {
  const dir = tmp();
  const { s, log } = withLog(dir);
  const entry = s.vault.entries[0];
  fs.mkdirSync(path.join(dir, "receipts.jsonl")); // appending to a folder fails
  const e = refused(() => s.resolveArgs({ text: "{{OTP_1}}" }, ACME));
  assert.deepEqual([e.code, e.reason], ["not_recorded", "release not recorded"]);
  assert.deepEqual([entry.meta.uses_left, entry.meta.sinks], [1, []]); // no use was counted
  fs.rmdirSync(path.join(dir, "receipts.jsonl"));
  assert.deepEqual(s.resolveArgs({ text: "{{OTP_1}}" }, ACME).args, { text: "482913" }); // still has its one use
  assert.equal(records(dir).length, 1);
  assert.equal(log.seq, 1);
});

test("several handles in one call are recorded together", () => {
  const dir = tmp();
  const s = make("browse_and_fill", { releaseLog: new EgressLog(dir, WRITER, false), approve: () => true });
  s.mask(OTP_MAIL + " Password: hunter2-xyz", new Source({ site: "https://acme.com" }));
  const handles = s.vault.entries.filter((e) => e.action === "handle").map((e) => e.standIn).sort();
  assert.ok(handles.length >= 2);
  s.resolveArgs({ a: handles[0], b: handles[1] }, ACME);
  const recs = records(dir);
  assert.deepEqual(recs.map((r) => r.handle), handles.slice(0, 2));
  assert.equal(recs[0].call, recs[1].call);
  assert.deepEqual(recs.map((r) => r.seq), [1, 2]);
  const first = fs.readFileSync(path.join(dir, "receipts.jsonl"), "utf-8").split("\n")[0];
  assert.equal(recs[1].prev, digest(Buffer.from(first)));
});

test("records never hold a value or its hash", () => {
  const dir = tmp();
  const { s } = withLog(dir, { approve: () => ({ allowed: true, by: "mia" }) });
  s.resolveArgs({ text: "{{OTP_1}}" }, ACME);
  refused(() => s.resolveArgs({ text: "{{OTP_1}}" }, new Sink({ tool: "type", site: "https://evil.example" })));
  const real = Buffer.from("482913");
  const sha = createHash("sha256").update(real).digest();
  const forbidden = ["482913", digest(real), sha.toString("hex"), sha.toString("base64"), real.toString("base64url"), real.toString("hex")];
  for (const line of fs.readFileSync(path.join(dir, "receipts.jsonl"), "utf-8").split("\n").filter((l) => l)) {
    const body = Buffer.from(line.split(".")[1], "base64url").toString();
    for (const needle of forbidden) assert.ok(!body.includes(needle), needle);
  }
  assert.deepEqual(verifyLog(dir, WRITER.publicKey, s.vault).problems, []);
});

test("call is the digest of the arguments with handles unfilled", () => {
  const dir = tmp();
  const { s } = withLog(dir);
  const args = { text: "{{OTP_1}}", n: 2.5, deep: [1, { b: null, a: true }], name: "é" };
  s.resolveArgs(args, ACME);
  assert.equal(records(dir)[0].call, digest(canonicalArgs(args)));
  assert.equal(canonicalArgs({ x: [1.0, 1e21, 0.1, -0, 100] }).toString(), '{"x":[1,1e+21,0.1,0,100]}');
});

test("a session without a release log writes nothing", () => {
  const s = make("browse_and_fill");
  s.mask(OTP_MAIL, new Source({ sender: "no-reply@acme.com" }));
  assert.deepEqual(s.resolveArgs({ text: "{{OTP_1}}" }, ACME).args, { text: "482913" });
  assert.equal(s.releaseLog, null);
});

test("release and egress records share one chain", () => {
  const dir = tmp();
  const log = new EgressLog(dir, WRITER);
  const s = make("browse_and_fill", { releaseLog: log });
  const m = s.mask(OTP_MAIL, new Source({ sender: "no-reply@acme.com" }));
  const payload = Buffer.from(JSON.stringify({ messages: [{ role: "user", content: m.text }] }));
  s.recordEgress(log, payload, "api.example.com");
  s.resolveArgs({ text: "{{OTP_1}}" }, ACME);
  s.recordEgress(log, payload, "api.example.com");
  const report = verifyLog(dir, WRITER.publicKey, s.vault);
  assert.deepEqual([report.receipts, report.releases, report.rechecked, report.problems], [3, 1, 2, []]);
  assert.deepEqual(records(dir).map((r) => r.type), ["egress", "release", "egress"]);
  const reopened = new EgressLog(dir, WRITER);
  assert.deepEqual([reopened.seq, reopened.prev], [3, log.prev]);
});

// verifyLog on release records

function forge(dir: string, over: Record<string, any> = {}) {
  const log = new EgressLog(dir, WRITER, false);
  log.recordRelease({
    session: "s1", now: NOW, handle: "{{OTP_1}}", data: "OTP", source: "acme.com", sink: { tool: "type", site: "acme.com" },
    call: digest(Buffer.from("x")), decision: "allow", authority: { kind: "binding" }, ...over,
  } as any);
}

test("verifyLog finds a real value hidden in a record", () => {
  const { s } = withLog(tmp());
  const dir = tmp();
  forge(dir, { authority: { kind: "person", by: "code 482913" } });
  const report = verifyLog(dir, WRITER.publicKey, s.vault);
  assert.ok(report.problems.some((p) => p.includes("known value") && p.includes("record")));
  assert.equal(report.leaks, 1);
  assert.ok(!report.problems.join(" ").includes("482913"));
});

for (const [over, field] of [
  [{ handle: "OTP_1" }, "handle"], [{ data: "otp" }, "data"], [{ call: "sha-256:short" }, "call"], [{ usesLeft: -1 }, "uses_left"],
  [{ sink: { tool: "type" } }, "sink"],
] as [Record<string, any>, string][]) {
  test(`verifyLog flags a malformed release: ${field}`, () => {
    const dir = tmp();
    if (field === "sink") {
      const body = releaseBody({
        session: "s1", now: NOW, handle: "{{OTP_1}}", data: "OTP", source: null, sink: { tool: "type", site: null },
        call: digest(Buffer.from("x")), decision: "allow", authority: { kind: "binding" },
      }, 1, null);
      body.sink = { tool: "type" };
      fs.writeFileSync(path.join(dir, "receipts.jsonl"), WRITER.sign(body, "opn-release+jws") + "\n");
    } else {
      forge(dir, over);
    }
    const problems = verifyLog(dir, WRITER.publicKey).problems;
    assert.ok(problems.some((p) => p.includes(`release 1: ${field} is not valid`)), problems.join("; "));
  });
}

test("the writer refuses to sign an unlisted code or kind", () => {
  assert.throws(() => forge(tmp(), { decision: "deny", code: "not_recorded", reason: "x" }), RangeError);
  assert.throws(() => forge(tmp(), { decision: "deny", code: "made_up", reason: "x" }), RangeError);
  assert.throws(() => forge(tmp(), { authority: { kind: "model" } }), RangeError);
});

test("a tampered release line breaks the chain", () => {
  const dir = tmp();
  const { s } = withLog(dir);
  refused(() => s.resolveArgs({ text: "{{OTP_1}}" }, new Sink({ tool: "type", site: "https://evil.example" })));
  s.resolveArgs({ text: "{{OTP_1}}" }, ACME);
  const lines = fs.readFileSync(path.join(dir, "receipts.jsonl"), "utf-8").split("\n").filter((l) => l);
  fs.writeFileSync(path.join(dir, "receipts.jsonl"), lines[1] + "\n"); // drop the first record
  const problems = verifyLog(dir, WRITER.publicKey).problems;
  assert.ok(problems.some((p) => p.includes("sequence number") || p.includes("chain broken")));
});

// Checkpoints

function sixRecords(dir: string) {
  const log = new EgressLog(dir, WRITER, false);
  for (let n = 0; n < 6; n++) {
    log.recordRelease({
      session: "s1", now: NOW + n, handle: "{{OTP_1}}", data: "OTP", source: "acme.com", sink: { tool: "type", site: "acme.com" },
      call: digest(Buffer.from([n])), decision: "allow", authority: { kind: "binding" },
    });
  }
  return log;
}

const linesOf = (dir: string) => fs.readFileSync(path.join(dir, "receipts.jsonl"), "utf-8").split("\n").filter((l) => l);
const cutTo = (dir: string, n: number) => fs.writeFileSync(path.join(dir, "receipts.jsonl"), linesOf(dir).slice(0, n).map((l) => l + "\n").join(""));
const anchorAt = (lines: string[], seq: number, signer = ANCHOR, session = "s1") =>
  makeCheckpoint(signer, { session, seq, head: digest(Buffer.from(lines[seq - 1])), now: NOW });
const brief = (r: ReturnType<typeof verifyLog>) => [r.problems, r.provenTo, r.status, r.reason];

test("a log cut short is a prefix without an anchor", () => {
  const dir = tmp();
  sixRecords(dir);
  cutTo(dir, 4);
  assert.deepEqual(brief(verifyLog(dir, WRITER.publicKey)), [[], null, "prefix", "no_anchor"]);
});

test("an anchor past the end shows the cut", () => {
  const dir = tmp();
  const log = sixRecords(dir);
  const all = linesOf(dir);
  const cp = log.checkpoint(ANCHOR, { session: "s1", now: NOW });
  cutTo(dir, 4);
  const r = verifyLog(dir, WRITER.publicKey, null, { anchors: [cp], anchorKey: ANCHOR.publicKey });
  assert.deepEqual(r.problems, ["anchor at seq 6: the log was cut off after seq 4"]);
  assert.deepEqual([r.provenTo, r.status], [null, "prefix"]);
  assert.equal(cp, anchorAt(all, 6));
});

test("an anchor inside the log proves that far", () => {
  const dir = tmp();
  sixRecords(dir);
  const lines = linesOf(dir);
  cutTo(dir, 4);
  const r = verifyLog(dir, WRITER.publicKey, null, { anchors: [anchorAt(lines, 3)], anchorKey: ANCHOR.publicKey });
  assert.deepEqual(brief(r), [[], 3, "prefix", "unanchored_tail"]);
});

test("an anchor at the last record is complete", () => {
  const dir = tmp();
  sixRecords(dir);
  const lines = linesOf(dir);
  const r = verifyLog(dir, WRITER.publicKey, null, { anchors: [anchorAt(lines, 3), anchorAt(lines, 6)], anchorKey: ANCHOR.publicKey });
  assert.deepEqual(brief(r), [[], 6, "complete", null]);
});

test("an anchor whose head does not match is a problem", () => {
  const dir = tmp();
  sixRecords(dir);
  const wrong = makeCheckpoint(ANCHOR, { session: "s1", seq: 3, head: digest(Buffer.from("another log")), now: NOW });
  const r = verifyLog(dir, WRITER.publicKey, null, { anchors: [wrong], anchorKey: ANCHOR.publicKey });
  assert.ok(r.problems.some((p) => p.includes("anchor at seq 3: head does not match")));
  assert.deepEqual([r.provenTo, r.status], [null, "prefix"]);
});

test("an anchor signed by the writer's own key counts for nothing", () => {
  const dir = tmp();
  sixRecords(dir);
  const own = anchorAt(linesOf(dir), 6, WRITER);
  const r = verifyLog(dir, WRITER.publicKey, null, { anchors: [own], anchorKey: WRITER.publicKey });
  assert.ok(r.problems.some((p) => p.includes("the key that signs the log")));
  assert.deepEqual([r.provenTo, r.status], [null, "prefix"]);
});

test("a wrong key, wrong session or missing key is a problem", () => {
  const dir = tmp();
  sixRecords(dir);
  const lines = linesOf(dir);
  const other = Signer.fromSeed(Buffer.alloc(32, 9));
  let r = verifyLog(dir, WRITER.publicKey, null, { anchors: [anchorAt(lines, 6, other)], anchorKey: ANCHOR.publicKey });
  assert.deepEqual([r.problems, r.status], [["anchor 1: unknown key"], "prefix"]);
  r = verifyLog(dir, WRITER.publicKey, null, { anchors: [anchorAt(lines, 6, ANCHOR, "s2")], anchorKey: ANCHOR.publicKey });
  assert.deepEqual(r.problems, ["anchor 1: belongs to another session"]);
  r = verifyLog(dir, WRITER.publicKey, null, { anchors: [anchorAt(lines, 6)] });
  assert.deepEqual(r.problems, ["anchors were given without an anchor_key to check them with"]);
});

test("a log cannot checkpoint itself", () => {
  const log = sixRecords(tmp());
  assert.throws(() => log.checkpoint(WRITER, { session: "s1", now: NOW }), RangeError);
  assert.throws(() => new EgressLog(tmp(), WRITER).checkpoint(ANCHOR, { session: "s1", now: NOW }), RangeError);
});

test("expectCount and expectLast still work", () => {
  const dir = tmp();
  const log = sixRecords(dir);
  const last = log.prev;
  cutTo(dir, 4);
  const problems = verifyLog(dir, WRITER.publicKey, null, { expectCount: 6, expectLast: last }).problems;
  assert.equal(problems.length, 2);
  assert.ok(problems[0].includes("expected 6 receipt(s), found 4"));
});

// Sensitive references stay opaque

test("the two forms are found and lookalikes are not", () => {
  const text = `a ${SREF_BARE} b ${SREF_BRACKET}`;
  assert.deepEqual(srefRegions(text).map(([b, e]) => text.slice(b, e)), [SREF_BARE, SREF_BRACKET]);
  for (const no of [
    "sref:email:short", "xsref:email:" + ULID, "sref:" + "k".repeat(33) + ":" + ULID, "sref:Email:" + ULID,
    "sref:email:" + ULID.toLowerCase(), "sref:email:" + ULID.slice(0, -1) + "I", "sref:email:" + ULID + "A",
    "sref:email:" + ULID + "-4111", "sref:email:" + ULID + "@gmail.com", "sref:email:" + ULID + ".dana@x.com",
    "sref:k:ABCDEFGHIJKLMNOPQRST-4111 1111 1111 1111", "sref:x:danareyes_personal_2024@gmail.com",
  ]) {
    assert.deepEqual(srefRegions(no), [], no);
  }
  const ended = `see sref:email:${ULID}. Then`;
  assert.deepEqual(srefRegions(ended).map(([b, e]) => ended.slice(b, e)), [`sref:email:${ULID}`]);
});

test("a reference is never masked", () => {
  const s = make("strict");
  const m = s.mask(`card ${SREF_BARE} and ${SREF_BRACKET} and Dana Reyes`);
  assert.ok(m.text.includes(SREF_BARE) && m.text.includes(SREF_BRACKET) && !m.text.includes("Dana"));
  assert.ok(m.replacements.every((r) => r.type !== "CARD"));
});

test("a reference is never a stand-in or restored", () => {
  const s = make("strict");
  s.mask(`${SREF_BARE} call (617) 555-0142`);
  const fake = s.vault.entries.find((e) => e.type === "PHONE")!.standIn;
  const digits = [...fake].filter((c) => c >= "0" && c <= "9").join("");
  assert.equal(s.restore(`${SREF_BARE} ${SREF_BRACKET}`), `${SREF_BARE} ${SREF_BRACKET}`);
  const inside = "sref:contact:ABCDEFGH" + digits + "JKMNPQRS";
  assert.ok(srefRegions(inside).length > 0);
  assert.equal(s.restore(inside), inside); // a fake's digits inside a reference stay
  assert.equal(s.restore(`call ${digits}`), "call 6175550142"); // the same digits outside one are restored
  assert.deepEqual(s.unknownStandIns(`${SREF_BARE} ${SREF_BRACKET}`), []);
});

test("a reference split across stream chunks is never restored", () => {
  const s = make("strict");
  s.mask("call (617) 555-0142");
  const fake = s.vault.entries.find((e) => e.type === "PHONE")!.standIn;
  const digits = [...fake].filter((c) => c >= "0" && c <= "9").join("");
  const text = "ok " + "x".repeat(60) + " sref:contact:ABCDEFGH" + digits + "JKMNPQRS done " + "y".repeat(200);
  for (const size of [1, 3, 7, 50]) {
    const st = s.stream();
    let out = "";
    for (let i = 0; i < text.length; i += size) out += st.feed(text.slice(i, i + size));
    assert.equal(out + st.flush(), text, String(size));
  }
});

test("a reference is never filled and a handle never resolves to one", () => {
  const s = make("browse_and_fill");
  s.mask(OTP_MAIL, new Source({ sender: "no-reply@acme.com" }));
  const args = { ref: SREF_BARE, other: SREF_BRACKET };
  const r = s.resolveArgs(args, ACME);
  assert.deepEqual([r.args, r.report], [args, []]); // not restored, not flagged as something the model wrote
  assert.equal(refused(() => s.resolveArgs({ t: "{{SREF_1}}" }, ACME)).code, "unknown_handle");
  assert.deepEqual(s.resolveArgs({ t: "{{sref_1}}" }, ACME).args, { t: "{{sref_1}}" }); // not a handle at all
});

test("a reference is never an egress leak", () => {
  const s = make("strict");
  s.mask("Hi Dana,\nok");
  const payload = JSON.stringify({ messages: [{ role: "user", content: `use ${SREF_BARE} and ${SREF_BRACKET}` }] });
  assert.deepEqual(s.checkEgress(payload), []);
  assert.ok(s.checkEgress("use 4242 4242 4242 4242 and " + SREF_BARE).length > 0); // a real card number beside one still is
});

// A value stuck to a reference is not hidden by it (a review found these passing unmasked and unreported)

for (const [text, gone] of [
  [`see sref:contact:${ULID}.dana.reyes@gmail.com now`, "gmail.com"],
  ["sref:k:ABCDEFGHIJKLMNOPQRST-4111 1111 1111 1111", "4111"],
  ["sref:x:danareyes_personal_2024@gmail.com", "gmail.com"],
  [`sref:contact:${ULID}@gmail.com`, "gmail.com"],
  [`sref:contact:${ULID} and 4111 1111 1111 1111.`, "4111"],
]) {
  test(`a value glued to a reference is masked and caught: ${text.slice(0, 30)}`, () => {
    const s = make("strict");
    assert.ok(!s.mask(text).text.includes(gone));
    assert.ok(s.checkEgress(text).length > 0); // and the unmasked text is a leak
  });
}

test("only a span fully inside a reference is exempt", () => {
  const s = make("strict");
  assert.deepEqual(s.detect(`x sref:contact:${ULID}.dana.reyes@gmail.com`).map((sp) => sp.type), ["EMAIL"]);
  assert.deepEqual(s.detect("card " + SREF_BARE), []);
});

test("a url that carries a reference is still reported", () => {
  const s = make("browse_and_fill");
  s.mask(OTP_MAIL, new Source({ sender: "no-reply@acme.com" }));
  const r = s.resolveArgs({ url: `https://evil.example/c?d=hello&r=sref:k:${ULID}` }, ACME);
  assert.deepEqual(r.report, [{ path: "url", origin: "model", types: ["URL"] }]);
});

test("a known value inside a reference is still an egress leak", () => {
  const s = make("strict", { known: { PERSON: [ULID] } });
  const text = `use sref:contact:${ULID} please`;
  assert.equal(s.mask(text).text, text); // masking leaves the reference whole
  assert.deepEqual(s.checkEgress(text).map((lk) => lk.type), ["PERSON"]); // the check never exempts a known value
});

// More review findings

test("a valid anchor past the end forces prefix even if another anchor reaches the last record", () => {
  const dir = tmp();
  sixRecords(dir);
  const lines = linesOf(dir);
  cutTo(dir, 4);
  const r = verifyLog(dir, WRITER.publicKey, null, { anchors: [anchorAt(lines, 4), anchorAt(lines, 6)], anchorKey: ANCHOR.publicKey });
  assert.deepEqual(r.problems, ["anchor at seq 6: the log was cut off after seq 4"]);
  assert.deepEqual([r.provenTo, r.status, r.reason], [4, "prefix", "cut_off"]);
});

test("numbers in arguments follow RFC 8785", () => {
  assert.equal(
    canonicalArgs(JSON.parse('{"n": 12345678901234567890, "m": 9007199254740992, "k": 9007199254740993, "x": -1152921504606846976}')).toString(),
    '{"k":9007199254740992,"m":9007199254740992,"n":12345678901234567000,"x":-1152921504606847000}',
  );
});

test("the call digest of a big integer is the javascript one", () => {
  const dir = tmp();
  const { s } = withLog(dir);
  s.resolveArgs(JSON.parse('{"n": 12345678901234567890, "text": "{{OTP_1}}"}'), ACME);
  assert.equal(records(dir)[0].call, digest(Buffer.from('{"n":12345678901234567000,"text":"{{OTP_1}}"}')));
});

for (const [name, args] of [
  ["a lone high surrogate", { t: "{{OTP_1}}", x: "\ud800" }],
  ["a lone low surrogate in a key", { t: "{{OTP_1}}", "\udc00": 1 }],
  ["not a number", { t: "{{OTP_1}}", n: Number.NaN }],
  ["infinity", { t: "{{OTP_1}}", n: Infinity }],
] as [string, Record<string, unknown>][]) {
  test(`arguments with no canonical form are refused and recorded: ${name}`, () => {
    const dir = tmp();
    const { s } = withLog(dir);
    const entry = s.vault.entries[0];
    const e = refused(() => s.resolveArgs(args, ACME));
    assert.deepEqual([e.code, e.reason], ["malformed", "malformed arguments"]);
    assert.deepEqual([entry.meta.uses_left, entry.meta.sinks], [1, []]); // nothing was filled or counted
    const rec = records(dir)[0];
    assert.deepEqual([rec.decision, rec.code, rec.call], ["deny", "malformed", digest(Buffer.from("malformed"))]);
    assert.deepEqual(verifyLog(dir, WRITER.publicKey, s.vault).problems, []);
  });
}

test("malformed arguments are refused without a log and ignored without a handle", () => {
  const s = make("browse_and_fill");
  s.mask(OTP_MAIL, new Source({ sender: "no-reply@acme.com" }));
  assert.equal(refused(() => s.resolveArgs({ t: "{{OTP_1}}", x: "\ud800" }, ACME)).code, "malformed");
  assert.deepEqual(s.resolveArgs({ x: "\ud800" }, ACME).args, { x: "\ud800" });
});

test("a short write is finished, and a write that makes no progress throws before anything is filled", () => {
  const dir = tmp();
  const { s } = withLog(dir);
  const real = fsLive.writeSync;
  const calls: number[] = [];
  // a writeSync that never writes more than 7 bytes at a time
  const trickle = ((fd: number, buf: Buffer, off: number, len: number) => {
    calls.push(len);
    return real(fd, buf, off, Math.min(len, 7));
  }) as typeof fs.writeSync;
  const m = mock.method(fsLive, "writeSync", trickle);
  syncBuiltinESMExports();
  try {
    s.resolveArgs({ text: "{{OTP_1}}" }, ACME);
  } finally {
    m.mock.restore();
    syncBuiltinESMExports();
  }
  assert.ok(calls.length > 3);
  assert.equal(verifyLog(dir, WRITER.publicKey, s.vault).problems.length, 0);
  assert.equal(records(dir).length, 1);

  const dir2 = tmp();
  const { s: s2 } = withLog(dir2);
  const e2 = s2.vault.entries[0];
  const stuck = mock.method(fsLive, "writeSync", (() => 0) as typeof fs.writeSync);
  syncBuiltinESMExports();
  try {
    assert.equal(refused(() => s2.resolveArgs({ text: "{{OTP_1}}" }, ACME)).code, "not_recorded");
  } finally {
    stuck.mock.restore();
    syncBuiltinESMExports();
  }
  assert.equal(e2.meta.uses_left, 1);
});

test("verifyLog recomputes shown from the vault", () => {
  const { s } = withLog(tmp());
  const dir = tmp();
  forge(dir, { authority: { kind: "person", shown: digest(Buffer.from("what they saw")) } });
  assert.deepEqual(verifyLog(dir, WRITER.publicKey, s.vault).problems,
    ["release 1: shown does not match what the vault says the approver was given"]);
  const dir2 = tmp();
  forge(dir2, { handle: "{{OTP_7}}", authority: { kind: "person", shown: digest(Buffer.from("what they saw")) } });
  assert.deepEqual(verifyLog(dir2, WRITER.publicKey, s.vault).problems, ["release 1: shown names a handle the vault does not hold"]);
});

// The standing a release was decided under (0.5, from yaotsakpo on MCP PR 1913), and a Sensitive References audit id

test("a binding names the rule and the policy it came from", () => {
  const dir = tmp();
  const { s } = withLog(dir);
  refused(() => s.resolveArgs({ text: "{{OTP_1}}" }, new Sink({ tool: "type", site: "https://evil.example" })));
  s.resolveArgs({ text: "{{OTP_1}}" }, ACME);
  const want = { kind: "binding", rule: "/rules/OTP", policy: loadProfile("browse_and_fill").digest };
  assert.deepEqual(records(dir).map((r) => r.authority), [want, want]);
  assert.deepEqual(verifyLog(dir, WRITER.publicKey, s.vault, { policies: [s.policy] }).problems, []);
  assert.deepEqual(verifyLog(dir, WRITER.publicKey, null, { policies: [s.policy.toDict()] }).problems, []);
});

test("a policy default is named as such", () => {
  const dir = tmp();
  const doc = { opn: "0.1", type: "policy", id: "all_handles", rules: {}, default: { action: "handle", tools: ["type"] } };
  const s = new Session(Policy.fromDict(doc), {
    vault: new Vault(Buffer.alloc(32), NOW), clock: () => NOW, releaseLog: new EgressLog(dir, WRITER, false),
  });
  s.mask(OTP_MAIL, new Source({ sender: "no-reply@acme.com" }));
  s.resolveArgs({ text: "{{OTP_1}}" }, ACME);
  assert.deepEqual(records(dir)[0].authority,
    { kind: "binding", rule: "/default", policy: digest(canonical(Policy.fromDict(doc).toDict())) });
  assert.deepEqual(verifyLog(dir, WRITER.publicKey, null, { policies: [doc] }).problems, []);
});

test("the standing is kept with the entry so a later policy cannot rewrite it", () => {
  const dir = tmp();
  const { s } = withLog(dir);
  const first = s.policy.digest;
  (s as any).policy = s.policy.tighten(loadProfile("strict")); // the app switches policy after the handle was made
  assert.notEqual(s.policy.digest, first);
  s.resolveArgs({ text: "{{OTP_1}}" }, ACME);
  assert.equal(records(dir)[0].authority.policy, first);
});

test("no standing where no rule decided", () => {
  const dir = tmp();
  const { s } = withLog(dir, { approve: () => ({ allowed: true, by: "mia" }) });
  refused(() => s.resolveArgs({ t: "{{OTP_9}}" }, ACME));
  refused(() => s.resolveArgs({ t: "{{OTP_1}}", x: "\ud800" }, ACME));
  s.resolveArgs({ t: "{{OTP_1}}" }, ACME);
  const auths = records(dir).map((r) => r.authority);
  assert.deepEqual(auths.slice(0, 2), [{ kind: "binding" }, { kind: "binding" }]); // unknown handle; malformed arguments
  assert.equal(auths[2].kind, "person");
  assert.ok(!("rule" in auths[2]) && !("policy" in auths[2]));
});

test("a vault from before 0.5 names only the kind", () => {
  const dir = tmp();
  const { s } = withLog(dir);
  delete s.vault.entries[0].meta.rule;
  delete s.vault.entries[0].meta.policy;
  s.resolveArgs({ text: "{{OTP_1}}" }, ACME);
  assert.deepEqual(records(dir)[0].authority, { kind: "binding" });
  assert.deepEqual(verifyLog(dir, WRITER.publicKey, s.vault, { policies: [s.policy] }).problems, []);
});

test("a tampered standing in the vault is not written", () => {
  const dir = tmp();
  const { s } = withLog(dir);
  s.vault.entries[0].meta.rule = "OTP"; // not a pointer: the record falls back to the kind alone
  s.resolveArgs({ text: "{{OTP_1}}" }, ACME);
  assert.deepEqual(records(dir)[0].authority, { kind: "binding" });
});

const P = digest(Buffer.from("p"));
for (const authority of [
  { kind: "binding", rule: "/rules/OTP" },
  { kind: "binding", policy: P },
  { kind: "person", by: "mia", rule: "/rules/OTP", policy: P },
  { kind: "consent", ref: "c1", digest: digest(Buffer.from("t")), rule: "/rules/OTP", policy: P },
  { kind: "binding", rule: "OTP", policy: P },
  { kind: "binding", rule: "/rules/otp", policy: P },
  { kind: "binding", rule: "/rules/OTP/uses", policy: P },
  { kind: "binding", rule: "/rules/OTP", policy: "browse_and_fill" },
]) {
  test(`the writer refuses a standing out of shape: ${JSON.stringify(authority)}`, () => {
    assert.throws(() => forge(tmp(), { authority }), RangeError);
  });
}

function signed(dir: string, set: Record<string, any>): void {
  const body = releaseBody({
    session: "s1", now: NOW, handle: "{{OTP_1}}", data: "OTP", source: null, sink: { tool: "type", site: null },
    call: digest(Buffer.from("x")), decision: "allow", authority: { kind: "binding" },
  }, 1, null);
  Object.assign(body, set);
  fs.writeFileSync(path.join(dir, "receipts.jsonl"), WRITER.sign(body, "opn-release+jws") + "\n");
}

for (const authority of [
  { kind: "binding", rule: "/rules/OTP" },
  { kind: "person", by: "mia", rule: "/rules/OTP", policy: P },
  { kind: "binding", rule: "/rules", policy: P },
]) {
  test(`verifyLog flags a standing out of shape: ${JSON.stringify(authority)}`, () => {
    const dir = tmp();
    signed(dir, { authority });
    assert.deepEqual(verifyLog(dir, WRITER.publicKey).problems, ["release 1: authority.rule or authority.policy is not valid"]);
  });
}

for (const [rule, data, problem] of [
  ["/rules/OTP", "OTP", false],
  ["/rules/CARD", "OTP", true], // the rule of another type
  ["/default", "OTP", true], // OTP has its own rule, so the default did not decide
  ["/default", "PERSON", true], // the default is tag, not handle
  ["/rules/EMAIL", "EMAIL", true], // EMAIL is fake, not handle
  ["/rules/NOPE", "NOPE", true], // no such rule
] as [string, string, boolean][]) {
  test(`verifyLog checks the rule against the policy: ${rule} for ${data}`, () => {
    const dir = tmp();
    const baf = loadProfile("browse_and_fill");
    forge(dir, { data, authority: { kind: "binding", rule, policy: baf.digest } });
    const got = verifyLog(dir, WRITER.publicKey, null, { policies: [loadProfile("strict"), baf] }).problems;
    assert.deepEqual(got, problem ? ["release 1: authority.rule is not the handle rule for the record's data type in that policy"] : []);
    assert.deepEqual(verifyLog(dir, WRITER.publicKey).problems, []); // without the policy there is nothing to check
  });
}

test("verifyLog flags a policy digest that matches no policy given", () => {
  const dir = tmp();
  forge(dir, { authority: { kind: "binding", rule: "/rules/OTP", policy: loadProfile("browse_and_fill").digest } });
  assert.deepEqual(verifyLog(dir, WRITER.publicKey, null, { policies: [loadProfile("strict")] }).problems,
    ["release 1: authority.policy is not the digest of any policy given"]);
});

test("an audit id goes into every record of its call", () => {
  const dir = tmp();
  const s = make("browse_and_fill", { releaseLog: new EgressLog(dir, WRITER, false) });
  s.mask(OTP_MAIL + " Password: hunter2-xyz", new Source({ site: "https://acme.com" }));
  const handles = s.vault.entries.filter((e) => e.action === "handle").map((e) => e.standIn).sort();
  refused(() => s.resolveArgs({ a: handles[0] }, new Sink({ tool: "type", site: "https://evil.example" }), { auditId: "evt-1" }));
  s.resolveArgs({ a: handles[0], b: handles[1] }, ACME, { auditId: "evt_01JD8Z.r-7" });
  s.resolveArgs({ a: handles[1] }, ACME);
  assert.deepEqual(records(dir).map((r) => r.audit_id ?? null), ["evt-1", "evt_01JD8Z.r-7", "evt_01JD8Z.r-7", null]);
  assert.deepEqual(verifyLog(dir, WRITER.publicKey, s.vault).problems, []);
});

test("an audit id passes through JSON text arguments", () => {
  const dir = tmp();
  const { s } = withLog(dir);
  assert.equal(s.resolveArgs('{"text": "{{OTP_1}}"}', ACME, { auditId: "evt-2" }).args, '{"text":"482913"}');
  assert.equal(records(dir)[0].audit_id, "evt-2");
});

for (const bad of ["", "e".repeat(129), "evt 1", "evt/1", "evt:1", "évt", "evt\n", 7, Buffer.from("evt"), ["evt"]]) {
  test(`a malformed audit id is refused before anything: ${JSON.stringify(bad)}`, () => {
    const dir = tmp();
    const { s, log } = withLog(dir);
    assert.throws(() => s.resolveArgs({ text: "{{OTP_1}}" }, ACME, { auditId: bad as any }), (e) => e instanceof TypeError || e instanceof RangeError);
    assert.deepEqual([log.seq, s.vault.entries[0].meta.uses_left], [0, 1]); // nothing written, no use counted
    assert.deepEqual(s.resolveArgs({ text: "{{OTP_1}}" }, ACME, { auditId: "E".repeat(128) }).args, { text: "482913" });
    assert.equal(records(dir)[0].audit_id, "E".repeat(128));
  });
}

test("an audit id is never looked up but a value in it is still caught", () => {
  const dir = tmp();
  const { s } = withLog(dir);
  // the writer treats the id as opaque: it does not refuse one that happens to hold a real value...
  s.resolveArgs({ text: "{{OTP_1}}" }, ACME, { auditId: "otp-482913" });
  // ...but the verifier's "no value in any record" check reads every field, the audit id included
  const report = verifyLog(dir, WRITER.publicKey, s.vault);
  assert.deepEqual(report.problems, ["release 1: 1 known value(s) found in the record"]);
  assert.equal(report.leaks, 1);
});

for (const value of ["", "a b", "x".repeat(129), 5]) {
  test(`verifyLog and the writer refuse an audit id out of shape: ${JSON.stringify(value)}`, () => {
    assert.throws(() => forge(tmp(), { auditId: value }), RangeError);
    const dir = tmp();
    signed(dir, { audit_id: value });
    assert.deepEqual(verifyLog(dir, WRITER.publicKey).problems, ["release 1: audit_id is not valid"]);
  });
}
