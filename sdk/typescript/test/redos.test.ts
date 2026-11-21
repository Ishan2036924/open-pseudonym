// Regex denial of service: functions that read hosts and text from untrusted input must stay linear on inputs built to
// make a backtracking regex try every split. `/\.+$/` on "a" + "." x 50,000 + "a" took about 1.8 s per call on a laptop
// (the work grows with the square of the length); the loops that replaced it take well under a millisecond.
import { test } from "node:test";
import assert from "node:assert/strict";
import { Session, Sink, Source, Vault } from "../src/index.ts";
import { isPublicSuffix, registrable } from "../src/fakes.ts";
import { boundSite, siteMatches } from "../src/handles.ts";
import { rstripDots, stripWs } from "../src/util.ts";

const N = 50_000;
const DOTS = "a" + ".".repeat(N) + "a"; // a long run of dots that is not at the end
const SPACES = "a" + " ".repeat(N) + "a";
const LIMIT_MS = 250; // the old patterns took seconds here; the new code takes well under 1 ms

function fast(label: string, f: () => unknown) {
  const t = performance.now();
  f();
  const ms = performance.now() - t;
  assert.ok(ms < LIMIT_MS, `${label} took ${ms.toFixed(0)} ms on a ${N}-character input`);
}

test("host helpers stay linear on a long inner run of dots (CodeQL js/polynomial-redos)", () => {
  fast("isPublicSuffix", () => isPublicSuffix(DOTS));
  fast("registrable", () => registrable(DOTS));
  fast("boundSite(sender)", () => boundSite({ sender: "x@" + DOTS }));
  fast("siteMatches(site)", () => siteMatches(DOTS, ["acme.com"]));
  fast("siteMatches(allowed)", () => siteMatches("acme.com", [DOTS, "*." + DOTS]));
  fast("stripWs", () => stripWs(SPACES));
});

test("the same inputs through the public API stay fast", () => {
  const s = new Session("browse_and_fill", { vault: new Vault(Buffer.alloc(32, 1), 1793836800), clock: () => 1793836800 });
  fast("mask with a hostile sender", () => s.mask("Your code is 482913.", new Source({ sender: "x@" + DOTS })));
  fast("resolve_args on a hostile sink", () => {
    try {
      s.resolveArgs({ t: "{{OTP_1}}" }, new Sink({ tool: "type", site: DOTS }));
    } catch { /* refused is fine; only the time matters */ }
  });
  fast("mask before a long run of spaces", () => s.mask("x" + " ".repeat(N) + "Dana Reyes said hi"));
});

test("rstripDots and stripWs keep Python's rstrip('.') and strip() results", () => {
  for (const [s, want] of [["", ""], ["...", ""], ["a.b..", "a.b"], ["a", "a"], [".a.", ".a"]] as const) {
    assert.equal(rstripDots(s), want);
  }
  for (const [s, want] of [["", ""], ["  ", ""], ["  a b\t\n", "a b"], ["　x ", "x"], ["a", "a"]] as const) {
    assert.equal(stripWs(s), want);
  }
});
