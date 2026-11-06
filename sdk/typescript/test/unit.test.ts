import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import {
  EgressLeak, EgressLog, FF1, HandleRefused, Policy, PolicyError, RefusedData, Session, Signer, Sink, Source, Vault,
  VaultError, loadProfile, profileNames, suggestProfile, verifyLog, LEVELS, loadLevel, type SessionOptions,
} from "../src/index.ts";

const NOW = 1793836800; // 2026-11-05 00:00 UTC, so a date without a year reads as 2026
const clock = () => NOW;

const TEXTS = [
  "From: Dana Reyes <dana.reyes@gmail.com>\nHi Sam,\nCall (617) 555-0142 on March 12, 2026.\nDana",
  "Invoice for Northwind Traders Inc. to 221 Baker Street, Apt 4; card 4242 4242 4242 4242.",
  "I will meet Priya Raman and Omar Haddad at https://meet.acme.com/r/9921xq on 2026-04-02.",
  "Your verification code is 482913. Password: Tr0ub4dor&3 for priya@acme.co.uk",
];

function session(profile: string | Policy = "strict", seed = 1, known: Record<string, string[]> = {}, extra: SessionOptions = {}) {
  return new Session(profile, { vault: new Vault(Buffer.alloc(32, seed), NOW), clock, known, ...extra });
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
  // a subdomain is not the host, since anyone may host a form there
  assert.throws(() => s.resolveArgs({ code: handle }, new Sink({ tool: "browser", site: "https://login.acme.com/verify" })), (e: any) => e instanceof HandleRefused && e.reason === "bound to a different site");
  const right = new Sink({ tool: "browser", site: "https://acme.com/verify" });
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
  const full = verifyLog(dir, signer.publicKey, s.vault);
  assert.deepEqual({ ...full, last: undefined }, { receipts: 2, rechecked: 2, leaks: 0, problems: [], last: undefined });
  assert.match(full.last!, /^sha-256:/);

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
    assert.deepEqual(new Set(s.checkEgress(payload).map((l) => l.type)), new Set(["CARD"]), payload);
  }
});

test("a name part that is also a common word does not raise false alarms", () => {
  const s = session("strict", 1, { PERSON: ["May Chen"] });
  s.mask("lunch with May Chen");
  assert.deepEqual(s.checkEgress("see you in May"), []);
});

test("an unbound handle is never filled", () => {
  const s = session("browse_and_fill");
  s.mask("password: Hunter2!xyz and card 4111 1111 1111 1111");
  for (const args of [{ b: "{{PASSWORD_1}}" }, { b: "{{CARD_1}}" }]) {
    assert.throws(() => s.resolveArgs(args, new Sink({ tool: "send_email", site: "https://evil.example" })),
      (e: any) => e instanceof HandleRefused && e.reason === "not bound to a site or tool");
  }
});

test("text cannot stretch a code's lifetime", () => {
  let now = NOW;
  const s = session("browse_and_fill", 1, {}, { clock: () => now });
  s.mask("Your code is 482913. It is valid for 999 hours.", new Source({ sender: "x@acme.com" }));
  now += 601; // past the profile's 600 seconds, far inside the 999 hours the text claims
  assert.throws(() => s.resolveArgs({ t: "{{OTP_1}}" }, new Sink({ tool: "type", site: "acme.com" })),
    (e: any) => e instanceof HandleRefused && e.reason === "expired");
});

test("text alone is capped at an hour", () => {
  const p = Policy.fromDict({ opn: "0.1", type: "policy", id: "x", rules: { OTP: { action: "handle" } } });
  let now = NOW;
  const s = session(p, 1, {}, { clock: () => now });
  s.mask("Your code is 482913, valid for 30 hours.", new Source({ sender: "x@acme.com" }));
  now += 3601;
  assert.throws(() => s.resolveArgs({ t: "{{OTP_1}}" }, new Sink({ tool: "type", site: "acme.com" })),
    (e: any) => e instanceof HandleRefused && e.reason === "expired");
});

test("tightening keeps every handle limit", () => {
  const p = loadProfile("strict").withRules({ OTP: { action: "handle" }, SSN: { action: "handle" } });
  assert.deepEqual(p.ruleFor("OTP").options, { uses: 1, ttl_s: 600 });
  assert.deepEqual(p.ruleFor("SSN").options, { ask: true });
  const doc = (id: string, rule: Record<string, any>) =>
    Policy.fromDict({ opn: "0.1", type: "policy", id, rules: { PASSWORD: { action: "handle", ...rule } } });
  const a = doc("a", { uses: 1, sites: ["acme.com"], ask: true });
  const b = doc("b", { uses: 5, sites: ["acme.com", "x.example"] });
  for (const t of [a.tighten(b), b.tighten(a)]) {
    assert.deepEqual(t.ruleFor("PASSWORD").options, { uses: 1, ask: true, sites: ["acme.com"] });
    assert.deepEqual(Object.keys(t.ruleFor("PASSWORD").options), ["uses", "ask", "sites"]);
  }
  const c = doc("c", { sites: ["other.example"] });
  assert.equal(a.tighten(c).ruleFor("PASSWORD").action, "drop"); // no site both allow: nothing may be filled
});

test("a real name equal to an earlier fake is still masked", () => {
  const s = session("draft_reply", 1);
  const fake = s.mask("Hi Dana,\nok").text.split("Hi ")[1].split(",")[0];
  const realText = `Hi ${fake},\nthis is a different person who really has that name`;
  const m = s.mask(realText);
  assert.ok(!m.text.startsWith(`Hi ${fake},`)); // masked like any other name
  assert.equal(s.restore(m.text), realText);
});

test("masking twice changes nothing when the app says so", () => {
  const s = session("draft_reply", 1, {}, { maskedInput: true });
  const once = s.mask(TEXTS[0]).text;
  assert.equal(s.mask(once).text, once);
});

test("shared hosting and backslash tricks are refused", () => {
  const s = session("browse_and_fill");
  s.mask("Your code is 482913", new Source({ sender: "no-reply@acme.github.io" }));
  for (const site of ["https://attacker.github.io/login", "https://evil.example\\@acme.github.io/"]) {
    assert.throws(() => s.resolveArgs({ t: "{{OTP_1}}" }, new Sink({ tool: "type", site })),
      (e: any) => e instanceof HandleRefused && e.reason === "bound to a different site", site);
  }
  assert.deepEqual(s.resolveArgs({ t: "{{OTP_1}}" }, new Sink({ tool: "type", site: "https://acme.github.io/2fa" })).args, { t: "482913" });
});

test("short codes are hidden again when history is resent", () => {
  const s = session("browse_and_fill");
  s.mask("Enter 4821 to verify", new Source({ sender: "x@acme.com" }));
  s.resolveArgs({ t: "{{OTP_1}}" }, new Sink({ tool: "type", site: "acme.com" }));
  const [msgs] = s.maskMessages([{ role: "tool", content: "typed 4821 into the box" }]);
  assert.ok(!msgs[0].content.includes("4821"));
});

test("name slugs in links are hidden", () => {
  const s = session("strict");
  const m = s.mask("I will meet Dana Reyes, see https://social.example.com/in/danareyes");
  assert.ok(!m.text.includes("danareyes"));
});

test("lowercase names are caught once known", () => {
  const s = session("strict");
  s.mask("I will meet Dana Reyes");
  assert.ok(!s.mask("dana reyes called back").text.includes("dana reyes"));
  assert.ok(s.checkEgress("then dana reyes said hi").length > 0);
});

test("verify reports missing payloads, cut tails and damaged lines", () => {
  const s = session("draft_reply");
  const dir = tempDir();
  const signer = Signer.fromSeed(Buffer.alloc(32));
  const log = new EgressLog(dir, signer);
  for (const text of ["Hi Dana,\nx", "Hi Sam,\ny", "Hi Omar,\nz"]) s.recordEgress(log, s.mask(text).text, "api.example.com");
  const full = verifyLog(dir, signer.publicKey, s.vault);
  assert.deepEqual(full.problems, []);
  assert.equal(full.receipts, 3);
  fs.unlinkSync(path.join(dir, "payloads", "000002.bin"));
  assert.ok(verifyLog(dir, signer.publicKey).problems.includes("receipt 2: its stored payload is missing"));
  const lines = fs.readFileSync(path.join(dir, "receipts.jsonl"), "utf-8").split("\n").filter((l) => l !== "");
  fs.writeFileSync(path.join(dir, "receipts.jsonl"), lines[0] + "\n");
  assert.ok(verifyLog(dir, signer.publicKey, null, { expectCount: 3 }).problems.at(-1)!.startsWith("expected 3"));
  assert.ok(verifyLog(dir, signer.publicKey, null, { expectLast: full.last }).problems.at(-1)!.startsWith("the last"));
  const b64 = (x: string) => Buffer.from(x).toString("base64url");
  const forged = b64('{"alg":"EdDSA","kid":"x","typ":"\\ud800"}') + "." + b64("{}") + ".AAAA";
  fs.writeFileSync(path.join(dir, "receipts.jsonl"), lines[0] + "\n" + forged + "\n");
  assert.ok(verifyLog(dir, signer.publicKey).problems.some((p) => p.includes("receipt 2")));
});

test("egress also runs a detection pass over content fields", () => {
  const s = session("strict");
  const bad = JSON.stringify({ messages: [{ role: "user", content: "SSN 123-45-6789" }] });
  assert.deepEqual(s.checkEgress(bad).map((l) => [l.type, l.entryId]), [["SSN", "detected"]]);
  const dir = tempDir();
  const log = new EgressLog(dir, Signer.generate());
  assert.throws(() => s.recordEgress(log, bad, "api.example.com"), EgressLeak);
  assert.equal(log.seq, 0);
  // a model name that looks like a date is structure, not content
  const ok = JSON.stringify({ model: "gpt-x-2024-08-06", messages: [{ role: "user", content: "hello there" }] });
  assert.deepEqual(s.checkEgress(ok), []);
  // a long integer written as a JSON number keeps every digit, even past what a double can hold exactly
  assert.deepEqual(s.checkEgress('{"c":5500005555555559}').map((l) => l.type), ["CARD"]);
});

test("levels always hide secrets and add more as they go up", () => {
  const secrets = ["CARD", "IBAN", "ROUTING", "BANK_ACCOUNT", "SSN", "API_KEY", "PASSWORD", "OTP"];
  for (const n of [1, 2, 3]) {
    const p = loadLevel(n);
    for (const t of secrets) assert.equal(p.ruleFor(t).action, "handle", `${n} ${t}`);
  }
  assert.equal(loadLevel(1).ruleFor("PERSON").action, "keep");
  assert.equal(loadLevel(2).ruleFor("EMAIL").action, "fake");
  assert.equal(loadLevel(3).ruleFor("PERSON").action, "fake");
  assert.equal(LEVELS[2].label, "Contacts");
  assert.throws(() => loadLevel(4), PolicyError);
});

test("a code that expires in 0 minutes is already expired, and a bare shared host binds nothing", () => {
  const s = new Session("browse_and_fill", { vault: new Vault(Buffer.alloc(32, 0), NOW), clock });
  s.mask("Your code is 482913, it expires in 0 minutes", new Source({ sender: "x@acme.com" }));
  assert.throws(() => s.resolveArgs({ t: "{{OTP_1}}" }, new Sink({ tool: "type", site: "acme.com" })), HandleRefused);
  const t = new Session("browse_and_fill", { vault: new Vault(Buffer.alloc(32, 1), NOW), clock });
  t.mask("Your code is 482913", new Source({ sender: "noreply@github.io" }));
  assert.throws(() => t.resolveArgs({ t: "{{OTP_1}}" }, new Sink({ tool: "type", site: "https://anyone.github.io" })), HandleRefused);
});

test("a code fills on the exact host only", () => {
  const s = new Session("browse_and_fill", { vault: new Vault(Buffer.alloc(32, 0), NOW), clock });
  const m = s.mask("Your Acme verification code is 482913. It expires in 10 minutes.", new Source({ sender: "no-reply@acme.com" }));
  assert.ok(m.text.includes("{{OTP_1}}") && !m.text.includes("482913"));
  assert.throws(() => s.resolveArgs({ text: "{{OTP_1}}" }, new Sink({ tool: "type", site: "https://login.acme.com/2fa" })),
    (e: any) => e instanceof HandleRefused && /bound to a different site/.test(e.message));
  const r = s.resolveArgs({ selector: "#code", text: "{{OTP_1}}" }, new Sink({ tool: "type", site: "https://acme.com/2fa" }));
  assert.deepEqual(r.args, { selector: "#code", text: "482913" });
});

test("a policy can allow subdomains on purpose", () => {
  const p = Policy.fromDict({ opn: "0.1", type: "policy", id: "x", rules: { OTP: { action: "handle", uses: 1, sites: ["*.acme.com"] } } });
  const s = session(p);
  s.mask("Your code is 482913");
  assert.deepEqual(s.resolveArgs({ t: "{{OTP_1}}" }, new Sink({ tool: "type", site: "https://login.acme.com" })).args, { t: "482913" });
});

test("known names match across any whitespace", () => {
  const s = session("strict");
  s.mask("I will meet Dana Reyes");
  for (const text of ["dana  reyes called", "dana\nreyes called", "dana reyes called", "dana\u00a0\treyes called"]) {
    assert.ok(!s.mask(text).text.toLowerCase().includes("reyes"), JSON.stringify(text));
    assert.ok(s.checkEgress(text).length > 0, JSON.stringify(text));
  }
});

test("keys of tool results are masked", () => {
  const s = session("strict");
  const [masked] = s.maskJson({ "dana.reyes@gmail.com": { name: "Dana Reyes" } });
  assert.ok(!JSON.stringify(masked).toLowerCase().includes("dana"));
});

test("long input stays fast", () => {
  const s = session("strict");
  const text = "a.".repeat(50_000) + " mail dana@acme.com";
  const t0 = performance.now();
  s.mask(text);
  assert.ok(performance.now() - t0 < 3000); // the email pattern is length-bounded
});

test("verify catches a missing log, orphan payloads and another session's log", () => {
  const s = session("draft_reply");
  const dir = tempDir();
  const signer = Signer.fromSeed(Buffer.alloc(32));
  const log = new EgressLog(dir, signer);
  for (const text of ["Hi Dana,\nx", "Hi Sam,\ny"]) s.recordEgress(log, s.mask(text).text, "api.example.com");
  assert.deepEqual(verifyLog(dir, signer.publicKey, null, { expectSession: s.id }).problems, []);
  assert.ok(verifyLog(dir, signer.publicKey, null, { expectSession: "x" }).problems.some((p) => p.includes("another session")));
  fs.writeFileSync(path.join(dir, "receipts.jsonl"), "");
  assert.ok(verifyLog(dir, signer.publicKey).problems.some((p) => p.includes("have no receipt")));
  fs.unlinkSync(path.join(dir, "receipts.jsonl"));
  assert.ok(verifyLog(dir, signer.publicKey).problems.includes("there is no receipts.jsonl in this folder"));
});

test("a signed thinking block goes back byte for byte, and personal data under a structural key is still masked", () => {
  const s = session("strict");
  const thinking = { type: "thinking", thinking: "Dana Reyes asked about Thursday.", signature: "c2lnbmF0dXJl" };
  const redacted = { type: "redacted_thinking", data: "Dana Reyes, 123-45-6789" };
  const [out] = s.maskMessages([
    { role: "assistant", content: [thinking, redacted] },
    { role: "user", content: [{ type: "input_image", image_url: "data:image/png;base64,iVBORw0KGgo=", detail: "Dana Reyes, SSN 123-45-6789" }] },
    { role: "user", content: "data:text/plain;base64,not base64 at all: SSN 123-45-6789" },
  ]);
  assert.equal(JSON.stringify(out[0].content), JSON.stringify([thinking, redacted]));
  assert.ok(!JSON.stringify(out[1]).includes("123-45-6789"));
  assert.equal(out[1].content[0].image_url, "data:image/png;base64,iVBORw0KGgo=", "real base64 is left alone");
  assert.ok(!JSON.stringify(out[2]).includes("123-45-6789"), "text dressed up as a data URL is masked");
});

test("checkEgress flags an email used as a JSON key", () => {
  const s = session("strict");
  assert.ok(s.checkEgress('{"dana@acme.com": 1}').some((l) => l.type === "EMAIL"));
  assert.deepEqual(s.checkEgress('{"model": "x", "n": 1}'), []);
});

test("a wildcard over a public suffix is refused", () => {
  for (const site of ["*.com", "*.github.io", "*.co.uk"]) {
    assert.throws(
      () => Policy.fromDict({ opn: "0.1", type: "policy", id: "x", rules: { OTP: { action: "handle", sites: [site] } } }),
      (e: any) => e instanceof PolicyError && e.message === `OTP: '${site}' covers a whole public suffix`,
    );
  }
  Policy.fromDict({ opn: "0.1", type: "policy", id: "x", rules: { OTP: { action: "handle", sites: ["*.acme.com"] } } });
});

test("a known contact's name parts are caught alone", () => {
  const s = session("strict", 1, { PERSON: ["Dana Reyes"] });
  const out = s.mask("Dana called, and later Reyes, Dana wrote back").text;
  assert.ok(!out.includes("Dana") && !out.includes("Reyes"), out);
});

test("verify notices an empty log and a removed payload folder", () => {
  const dir = tempDir();
  const s = session("strict");
  const signer = Signer.fromSeed(Buffer.alloc(32));
  s.recordEgress(new EgressLog(dir, signer), s.mask("Hi Dana,\nx").text, "api.example.com");
  fs.rmSync(path.join(dir, "payloads"), { recursive: true });
  assert.ok(verifyLog(dir, signer.publicKey, s.vault).problems.some((p) => p.includes("no stored payloads")));
  fs.writeFileSync(path.join(dir, "receipts.jsonl"), "");
  assert.ok(verifyLog(dir, signer.publicKey).problems.includes("the log holds no receipts"));
});

test("a signature outside a reasoning block is content, and inside one it is left alone", () => {
  const s = session("strict");
  const thinking = { type: "thinking", thinking: "plan", signature: "call me at (617) 555-0142" };
  const [out] = s.maskMessages([
    { role: "assistant", content: [thinking, { type: "text", text: "ok" }] },
    { role: "user", content: [{ type: "text", text: "hi" }], metadata: { signature: "call me at (617) 555-0142" } },
  ]);
  assert.equal(JSON.stringify(out[0]), JSON.stringify({ role: "assistant", content: [thinking, { type: "text", text: "ok" }] }));
  const [out2] = s.maskMessages([{ role: "user", metadata: { signature: "call me at (617) 555-0142" }, content: "x" }]);
  assert.ok(!JSON.stringify(out2).includes("555-0142"));
});

test("a base64 text document is decoded, masked and sent back as base64", () => {
  const s = session("strict");
  const doc = Buffer.from("Patient Dana Reyes, SSN 123-45-6789").toString("base64");
  const [out] = s.maskMessages([
    { role: "user", content: [{ type: "document", source: { type: "base64", media_type: "text/plain", data: doc } }] },
  ]);
  const sent = out[0].content[0].source;
  assert.equal(sent.media_type, "text/plain");
  const decoded = Buffer.from(sent.data, "base64").toString("utf-8");
  assert.ok(!decoded.includes("123-45-6789"), decoded);
  const [url] = s.maskValue(["data:text/plain;base64," + Buffer.from("SSN 123-45-6789").toString("base64")]);
  assert.ok(url[0].startsWith("data:text/plain;base64,"));
  assert.ok(!Buffer.from(url[0].slice("data:text/plain;base64,".length), "base64").toString().includes("123-45-6789"));
});

test("checkEgress reads a base64 text data: URL, and skips only the top-level model name", () => {
  const s = session("strict");
  const url = "data:text/plain;base64," + Buffer.from("SSN 123-45-6789").toString("base64");
  assert.ok(s.checkEgress(JSON.stringify({ input: url })).some((l) => l.type === "SSN"));
  assert.deepEqual(s.checkEgress(JSON.stringify({ input: "data:image/png;base64,iVBORw0KGgo=" })), []);
  assert.ok(s.checkEgress(JSON.stringify({ model: "x", items: [{ model: "dana@acme.com" }] })).some((l) => l.type === "EMAIL"));
});
