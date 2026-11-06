import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import {
  EgressLeak, EgressLog, FF1, HandleRefused, Policy, PolicyError, RefusedData, Session, Signer, Sink, Source, Vault,
  VaultError, loadProfile, profileNames, suggestProfile, verifyLog,
} from "../src/index.ts";

const NOW = 1793836800; // 2026-11-05 00:00 UTC, so a date without a year reads as 2026
const clock = () => NOW;

const TEXTS = [
  "From: Dana Reyes <dana.reyes@gmail.com>\nHi Sam,\nCall (617) 555-0142 on March 12, 2026.\nDana",
  "Invoice for Northwind Traders Inc. to 221 Baker Street, Apt 4; card 4242 4242 4242 4242.",
  "I will meet Priya Raman and Omar Haddad at https://meet.acme.com/r/9921xq on 2026-04-02.",
  "Your verification code is 482913. Password: Tr0ub4dor&3 for priya@acme.co.uk",
];

function session(profile = "strict", seed = 1, known: Record<string, string[]> = {}) {
  return new Session(profile, { vault: new Vault(Buffer.alloc(32, seed), NOW), clock, known });
}

function tempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "opn-"));
}

// A small repeatable generator, so a failing chunking can be rerun.
function lcg(seed: number) {
  let x = seed >>> 0;
  return (n: number) => {
    x = (Math.imul(x, 1664525) + 1013904223) >>> 0;
    return x % n;
  };
}

test("mask then restore (revealing handles) gives back the original text", () => {
  for (const profile of ["draft_reply", "strict", "browse_and_fill"]) {
    for (const text of TEXTS) {
      const s = session(profile);
      const masked = s.mask(text, new Source({ sender: "no-reply@acme.com" }));
      assert.notEqual(masked.text, text);
      assert.equal(s.restore(masked.text, true), text, `${profile}: ${text}`);
    }
  }
});

test("restoring without reveal shows a short description of a secret, never the secret", () => {
  const s = session("draft_reply");
  const masked = s.mask("Your Acme verification code is 482913.", new Source({ sender: "no-reply@acme.com" }));
  const shown = s.restore(masked.text);
  assert.ok(!shown.includes("482913"));
  assert.match(shown, /one-time code/);
});

test("a streamed restore equals a whole restore for any chunking", () => {
  for (let seed = 0; seed < 12; seed++) {
    const s = session("strict", seed + 1);
    const masked = s.mask(TEXTS[0] + "\n" + TEXTS[2]).text;
    const pick = lcg(seed);
    const st = s.stream();
    const out: string[] = [];
    for (let i = 0; i < masked.length;) {
      const n = 1 + pick(9);
      out.push(st.feed(masked.slice(i, i + n)));
      i += n;
    }
    out.push(st.flush());
    assert.equal(out.join(""), s.restore(masked), `seed ${seed}`);
  }
});

test("a stream never splits an emoji in half, even when the chunks do", () => {
  const s = session("strict");
  const masked = s.mask("Dana Reyes 😀😀 wrote this " + "😀".repeat(70) + " and Dana again 😀😀").text;
  const st = s.stream();
  const pieces: string[] = [];
  for (const unit of masked.split("")) pieces.push(st.feed(unit)); // one UTF-16 unit at a time
  pieces.push(st.flush());
  for (const p of pieces) assert.equal(p, p.toWellFormed(), "a piece ended inside a surrogate pair");
  assert.equal(pieces.join(""), s.restore(masked));
});

test("the same real value always gets the same stand-in, and a model reformatting still restores", () => {
  const s = session("draft_reply");
  const a = s.mask("Call (617) 555-0142");
  const b = s.mask("Again: 617-555-0142");
  const fakeDigits = (t: string) => t.replace(/[^0-9]/g, "");
  assert.equal(fakeDigits(a.text.slice("Call ".length)), fakeDigits(b.text.slice("Again: ".length)));
  const digits = fakeDigits(a.text);
  assert.equal(s.restore(`I'll ring ${digits.slice(0, 3)}.${digits.slice(3, 6)}.${digits.slice(6)}.`), "I'll ring 617.555.0142.");
});

test("a handle is refused on the wrong site and filled on the right one", () => {
  const s = session("draft_reply");
  const masked = s.mask("Your Acme verification code is 482913.", new Source({ sender: "no-reply@acme.com" }));
  const handle = /\{\{OTP_1\}\}/.exec(masked.text)![0];
  const wrong = new Sink({ tool: "browser", site: "https://evil.example/login" });
  assert.throws(() => s.resolveArgs({ code: handle }, wrong), (e: any) => e instanceof HandleRefused && e.reason === "bound to a different site");
  // lookalike hosts do not count as the bound site either
  assert.throws(() => s.resolveArgs({ code: handle }, new Sink({ tool: "browser", site: "https://acme.com.evil.example/" })), HandleRefused);
  const right = new Sink({ tool: "browser", site: "https://login.acme.com/verify" });
  assert.deepEqual(s.resolveArgs({ code: handle }, right).args, { code: "482913" });
  // the strict profile's OTP rule allows one use
  assert.throws(() => s.resolveArgs({ code: handle }, right), (e: any) => e instanceof HandleRefused && e.reason === "already used");
});

test("a handle the model invented is refused", () => {
  const s = session("draft_reply");
  assert.throws(() => s.resolveArgs({ code: "{{OTP_9}}" }, new Sink({ tool: "x" })), (e: any) => e.reason === "unknown handle");
});

test("the approval callback can say no", () => {
  const s = new Session("draft_reply", { vault: new Vault(Buffer.alloc(32, 1), NOW), clock, approve: () => false });
  const masked = s.mask("Your Acme verification code is 482913.", new Source({ sender: "no-reply@acme.com" }));
  const handle = /\{\{OTP_1\}\}/.exec(masked.text)![0];
  assert.throws(() => s.resolveArgs({ code: handle }, new Sink({ site: "https://acme.com" })), (e: any) => e.reason === "not approved");
});

test("egress: a planted leak is found, a clean payload passes, and the receipt chain verifies", () => {
  const s = session("strict");
  const masked = s.mask(TEXTS[0]).text;
  const clean = JSON.stringify({ messages: [{ role: "user", content: masked }] });
  assert.deepEqual(s.checkEgress(clean), []);

  const planted = JSON.stringify({ messages: [{ role: "user", content: masked + " (cc dana.reyes@gmail.com)" }] });
  assert.ok(s.checkEgress(planted).some((l) => l.type === "EMAIL"));
  // an escaped name inside JSON is still read
  assert.ok(s.checkEgress('{"x":"Dana\\u0020Reyes"}').some((l) => l.type === "PERSON"));

  const dir = tempDir();
  const signer = Signer.generate();
  const log = new EgressLog(dir, signer);
  s.recordEgress(log, clean, "api.example.com");
  s.recordEgress(log, clean, "api.example.com");
  assert.throws(() => s.recordEgress(log, planted, "api.example.com"), EgressLeak);
  assert.equal(log.seq, 2);
  assert.deepEqual(verifyLog(dir, signer.publicKey, s.vault), { receipts: 2, rechecked: 2, leaks: 0, problems: [] });

  // a payload swapped after the fact no longer matches its receipt
  fs.writeFileSync(path.join(dir, "payloads", "000002.bin"), "something else");
  const report = verifyLog(dir, signer.publicKey);
  assert.ok(report.problems.some((p) => p.includes("does not match its digest")));
  // and a receipt checked against the wrong key is not trusted
  assert.ok(verifyLog(dir, Signer.generate().publicKey).problems.length > 0);
});

test("vault: save and load round trip, wrong key fails", () => {
  const s = session("strict");
  s.mask(TEXTS[0]);
  const dir = tempDir();
  const file = path.join(dir, "vault.json");
  const key = Buffer.alloc(32, 7);
  s.vault.save(file, key);
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  const back = Vault.load(file, key);
  assert.deepEqual(back.toJSON(), s.vault.toJSON());
  assert.throws(() => Vault.load(file, Buffer.alloc(32, 8)), VaultError);
  assert.throws(() => Vault.load(file, Buffer.alloc(16, 7)), Error);
  // a damaged file is reported the same way
  const blob = fs.readFileSync(file);
  blob[blob.length - 8] ^= 1;
  assert.throws(() => Vault.decrypt(blob, key), VaultError);

  // the loaded vault carries on where the old one stopped: same real value, same stand-in
  const again = new Session("strict", { vault: back, clock });
  assert.equal(again.mask(TEXTS[0]).text, s.mask(TEXTS[0]).text);
});

test("policy: code can tighten but never loosen", () => {
  const strict = loadProfile("strict");
  assert.throws(() => strict.withRules({ OTP: { action: "keep" } }), (e: any) => e instanceof PolicyError && /cannot be loosened/.test(e.message));
  assert.throws(() => strict.withRules({ PERSON: { action: "tag" }, SSN: { action: "fake" } }), PolicyError);
  assert.equal(strict.withRules({ PERSON: { action: "drop" } }).ruleFor("PERSON").action, "drop");
  const both = loadProfile("schedule").tighten(loadProfile("summarize"));
  assert.equal(both.ruleFor("EMAIL").action, "drop");
  assert.notEqual(both.digest, strict.digest);
  assert.throws(() => Policy.fromDict({ type: "policy", id: "x", rules: { PERSON: { action: "shift" } } }), /only dates can be shifted/);
  assert.throws(() => Policy.fromDict({ type: "policy", id: "x", rules: { PERSON: { action: "fake", uses: 1 } } }), /do not apply/);
});

test("policy: a refuse rule stops the request", () => {
  const policy = Policy.fromDict({ type: "policy", id: "r", rules: { SSN: { action: "refuse" } }, default: { action: "tag" } });
  const s = new Session(policy, { vault: new Vault(Buffer.alloc(32, 1), NOW), clock });
  assert.throws(() => s.mask("my ssn is 123-45-6789"), (e: any) => e instanceof RefusedData && e.type === "SSN");
});

test("profiles: every shipped profile loads, and tool names suggest one", () => {
  const names = profileNames();
  assert.ok(names.includes("strict") && names.includes("draft_reply"));
  for (const n of names) assert.equal(loadProfile(n).id, n);
  assert.throws(() => loadProfile("../strict"), /no built-in profile/);
  assert.equal(suggestProfile(["send_email"]), "draft_reply");
  assert.equal(suggestProfile(["calendar_lookup"]), "schedule");
  assert.equal(suggestProfile(["something_else"]), "strict");
});

test("format-preserving encryption: format kept, decrypts with the key alone", () => {
  const s = new Session(Policy.fromDict({
    type: "policy", id: "fpe", rules: { CARD: { action: "fpe" }, PHONE: { action: "fpe" }, SSN: { action: "fpe" } },
  }), { vault: new Vault(Buffer.alloc(32, 5), NOW), clock });
  const masked = s.mask("card 4242 4242 4242 4242, phone (617) 555-0142, ssn 123-45-6789").text;
  assert.match(masked, /card \d{4} \d{4} \d{4} \d{4}, phone \(617\) \d{3}-\d{4}, ssn \d{3}-\d{2}-\d{4}/);
  assert.ok(!masked.includes("4242 4242 4242 4242"));
  const stand = s.vault.entries.filter((e) => e.action === "fpe");
  const back = Object.fromEntries(stand.map((e) => [e.type, s.fpeDecrypt(e.type, e.standIn)]));
  assert.deepEqual(back, { CARD: "4242 4242 4242 4242", PHONE: "(617) 555-0142", SSN: "123-45-6789" });
  const f = new FF1(Buffer.alloc(16, 1));
  assert.deepEqual(f.decrypt(f.encrypt([1, 2, 3, 4, 5, 6, 7])), [1, 2, 3, 4, 5, 6, 7]);
  assert.throws(() => f.encrypt([1, 2, 3]), /too short/);
});

test("masking chat messages and JSON keeps structure and puts notes where the handle first appears", () => {
  const s = session("draft_reply");
  const messages = [
    { role: "user", content: "Your Acme verification code is 482913. Mail dana.reyes@gmail.com" },
    { role: "assistant", content: [{ type: "text", text: "ok" }], tool_calls: [{ id: "t1", function: { name: "send", arguments: JSON.stringify({ to: "dana.reyes@gmail.com" }) } }] },
  ];
  const [out, notes] = s.maskMessages(messages, new Source({ sender: "no-reply@acme.com" }));
  assert.equal(notes.length, 1);
  assert.match(out[0].content, /\n\nNote: \{\{OTP_1\}\} is a 6-digit one-time code/);
  assert.equal(out[1].tool_calls[0].id, "t1");
  const args = JSON.parse(out[1].tool_calls[0].function.arguments);
  assert.ok(!JSON.stringify(args).includes("dana.reyes@gmail.com"));
  assert.deepEqual(s.restoreJson({ to: args.to }), { to: "dana.reyes@gmail.com" });
  assert.equal(messages[0].content.includes("Note:"), false, "the input is not changed");
});

test("the JWS signer is deterministic and loads back from PEM", () => {
  const seed = Buffer.alloc(32, 3);
  const a = Signer.fromSeed(seed);
  const b = Signer.fromSeed(seed);
  assert.equal(a.sign({ n: 1 }, "t+jws"), b.sign({ n: 1 }, "t+jws"));
  assert.equal(Signer.fromPem(a.toPem()).kid, a.kid);
  assert.throws(() => Signer.fromSeed(Buffer.alloc(16)), /32 bytes/);
});

test("a bare JSON number or string cannot hide a known card number", () => {
  const s = new Session("training_data", { vault: new Vault(Buffer.alloc(32, 0), NOW), clock });
  s.mask("card 4242 4242 4242 4242");
  for (const payload of ["4242424242424242", '"4242 4242 4242 4242"', "[4242424242424242]"]) {
    assert.deepEqual(s.checkEgress(payload).map((l) => l.type), ["CARD"], payload);
  }
});

test("a name part that is also a common word does not raise false alarms", () => {
  const s = session("strict", 1, { PERSON: ["May Chen"] });
  s.mask("lunch with May Chen");
  assert.deepEqual(s.checkEgress("see you May 5"), []);
});
