"""Writes the shared test vectors in vectors/.

Two kinds of case live here:
  - hand-written: checks, detections, policy merges and FF1 samples, with the answer worked out by a person from the
    spec. The script stops if the Python SDK disagrees with any of them.
  - recorded: masking scenarios where the exact fake values depend on the seed. The Python SDK (the reference) fills
    in the expected output; each recorded case also carries hand-checked properties that the script asserts, so a
    wrong reference cannot quietly become the truth.

Run it after changing the spec or the reference SDK, then run both SDKs' conformance checks.
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "sdk/python/src"))

from open_pseudonym import HandleRefused, Policy, Session, Signer, Sink, Source, Vault, load_profile  # noqa: E402
from open_pseudonym import checks  # noqa: E402
from open_pseudonym.drbg import Drbg  # noqa: E402
from open_pseudonym.fpe import FF1  # noqa: E402
from open_pseudonym.jcs import canonical, digest  # noqa: E402

NOW = 1793836800  # 2026-11-05 00:00:00 UTC
OUT = ROOT / "vectors"


def write(name, doc):
    OUT.mkdir(exist_ok=True)
    (OUT / f"{name}.json").write_text(json.dumps(doc, indent=1, ensure_ascii=False) + "\n")


def checks_vectors():
    cases = [
        ("card", "4242 4242 4242 4242", True), ("card", "4242 4242 4242 4241", False),
        ("card", "378282246310005", True), ("card", "2223003122003222", True), ("card", "1111111111111117", False),
        ("card", "0000000000000000", False),
        ("iban", "GB82 WEST 1234 5698 7654 32", True), ("iban", "GB83 WEST 1234 5698 7654 32", False),
        ("iban", "DE89370400440532013000", True), ("iban", "XX89370400440532013000", False),
        ("aba", "021000021", True), ("aba", "021000022", False), ("aba", "991000021", False),
        ("ssn", "123-45-6789", True), ("ssn", "666-45-6789", False), ("ssn", "900-45-6789", False),
        ("ssn", "123-00-6789", False), ("ssn", "123-45-0000", False),
        ("phone", "(617) 555-0142", True), ("phone", "555-0142", False),
        ("name", "Dana Reyes", True), ("name", "New York", False), ("name", "Hi", False),
    ]
    fns = {"card": checks.card_ok, "iban": checks.iban_ok, "aba": checks.aba_ok, "ssn": checks.ssn_ok,
           "phone": checks.phone_ok, "name": checks.name_ok}
    for check, value, ok in cases:
        assert fns[check](value) == ok, (check, value)
    write("checks", {"description": "Checksums and sanity checks (spec 4.1). Hand-written.",
                     "cases": [{"check": c, "value": v, "ok": ok} for c, v, ok in cases]})


def drbg_vectors():
    seed = bytes(range(32))
    d = Drbg(seed)
    plan = [("first.f", 60), ("first.f", 60), ("last", 79), ("date.offset", 52), ("phone.line", 10),
            ("first.f", 60), ("x", 1), ("big", 1000003)]
    draws = [{"label": lab, "n": n, "value": d.below(lab, n)} for lab, n in plan]
    write("drbg", {
        "description": "HMAC-SHA256 counter-mode draws (spec 7.1). Values come from the reference SDK; the block "
                       "for (label 'first.f', counter 0) is given so the construction itself can be checked.",
        "seed": seed.hex(),
        "first_block": {"label": "first.f", "counter": 0, "hex": Drbg(seed).block("first.f").hex()},
        "derive": {"purpose": "fpe", "hex": Drbg(seed).derive("fpe").hex()},
        "draws": draws,
    })


def ff1_vectors():
    key = "2B7E151628AED2A6ABF7158809CF4F3C"
    nist = [
        {"key": key, "radix": 10, "tweak": "", "pt": "0123456789", "ct": "2433477484"},
        {"key": key, "radix": 10, "tweak": "39383736353433323130", "pt": "0123456789", "ct": "6124200773"},
        {"key": key, "radix": 36, "tweak": "3737373770717273373737", "pt": "0123456789abcdefghi",
         "ct": "a9tv40mll9kdu509eum"},
    ]
    alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
    for c in nist:
        f = FF1(bytes.fromhex(c["key"]), c["radix"])
        out = f.encrypt([alphabet.index(ch) for ch in c["pt"]], bytes.fromhex(c["tweak"]))
        assert "".join(alphabet[i] for i in out) == c["ct"], c
    k256 = "2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94"
    f = FF1(bytes.fromhex(k256))
    extra = {"key": k256, "radix": 10, "tweak": "", "pt": "0123456789",
             "ct": f.encrypt_digits("0123456789")}
    assert extra["ct"] == "6657667009", "NIST FF1 AES-256 sample 7"
    write("ff1", {"description": "NIST SP 800-38G FF1 samples (AES-128 samples 1-3, AES-256 sample 7).",
                  "cases": nist + [extra]})


DETECT = [
    ("strict", "From: Dana Reyes <dana.reyes@gmail.com>\nHi Sam,\nCall (617) 555-0142 on March 12, 2026.",
     [["PERSON", "Dana Reyes"], ["EMAIL", "dana.reyes@gmail.com"], ["PERSON", "Sam"], ["PHONE", "(617) 555-0142"],
      ["DATE", "March 12, 2026"]]),
    ("strict", "card 4242 4242 4242 4242, not 4242 4242 4242 4241; IBAN GB82 WEST 1234 5698 7654 32",
     [["CARD", "4242 4242 4242 4242"], ["IBAN", "GB82 WEST 1234 5698 7654 32"]]),
    ("strict", "Your verification code is 482913. password: Tr0ub4dor&3 server 10.0.12.7",
     [["OTP", "482913"], ["PASSWORD", "Tr0ub4dor&3"], ["IP_ADDRESS", "10.0.12.7"]]),
    ("strict", "meet in New York with Priya Raman at 221 Baker Street, Apt 4 for $1,234.50",
     [["PERSON", "Priya Raman"], ["ADDRESS", "221 Baker Street, Apt 4"], ["MONEY", "$1,234.50"]]),
    ("strict", "SSN 123-45-6789, routing number 021000021, tracking 123456789, see https://acme.com/a?id=7.",
     [["SSN", "123-45-6789"], ["ROUTING", "021000021"], ["URL", "https://acme.com/a?id=7"]]),
    ("strict", "signed with Northwind Traders Inc. on 2026-02-30 and 12 Mar 2026",
     [["ORG", "Northwind Traders Inc."], ["DATE", "12 Mar 2026"]]),
    ("strict", 'hey Carmen, my login code was 551208. Thanks Femi Adebayo for the help!',
     [["PERSON", "Carmen"], ["OTP", "551208"], ["PERSON", "Femi Adebayo"]]),
    ("strict", '{"results": [{"name": "Ana Whitfield", "role": "approver"}, {"requester": "Dev Malhotra"}]}',
     [["PERSON", "Ana Whitfield"], ["PERSON", "Dev Malhotra"]]),
    ("strict", "Please pay Bilal Okonkwo back. Invoice to Grace Lindholm, 48 Harbor Road.",
     [["PERSON", "Bilal Okonkwo"], ["PERSON", "Grace Lindholm"], ["ADDRESS", "48 Harbor Road"]]),
]


def detect_vectors():
    cases = []
    for profile, text, expected in DETECT:
        s = Session(profile, Vault(seed=bytes(32)), clock=lambda: NOW)
        got = [[sp.type, sp.text] for sp in s.detect(text)]
        assert got == expected, (text, got)
        cases.append({"profile": profile, "now": NOW, "text": text, "spans": expected})
    write("detect", {"description": "Detection and merging (spec 4). Hand-written expectations.", "cases": cases})


def policy_vectors():
    cases = []
    a, b = load_profile("schedule"), load_profile("summarize")
    t = a.tighten(b)
    expected = {"EMAIL": "drop", "OTP": "drop", "DATE": "shift", "PERSON": "fake", "ORG": "fake",
                "LOCATION": "generalize", "MONEY": "keep", "CARD": "drop"}
    for k, v in expected.items():
        assert t.rule_for(k).action == v, k
    cases.append({"op": "tighten", "a": "schedule", "b": "summarize", "expect": expected})
    cases.append({"op": "with_rules", "base": "strict", "rules": {"OTP": {"action": "keep"}},
                  "error": "OTP: 'handle' cannot be loosened to 'keep'"})
    cases.append({"op": "with_rules", "base": "strict", "rules": {"PERSON": {"action": "drop"}},
                  "expect": {"PERSON": "drop"}})
    for name in ("strict", "draft_reply", "secrets_only"):
        cases.append({"op": "digest", "profile": name, "expect": load_profile(name).digest})
    write("policy", {"description": "Policies only tighten (spec 5). Digests are SHA-256 over canonical JSON.",
                     "cases": cases})


def run_steps(session, steps):
    """Runs a scenario through the reference SDK and records each result."""
    out = []
    for step in steps:
        step = dict(step)
        op = step["op"]
        if op == "mask":
            src = step.get("source")
            m = session.mask(step["text"], Source(**src) if src else None)
            step["expect"] = {"text": m.text, "notes": m.notes}
        elif op == "restore":
            text = step["text"]
            step["expect"] = session.restore(text, step.get("reveal", False))
        elif op == "stream":
            st = session.stream(step.get("reveal", False))
            pieces, i = [], 0
            for n in step["chunks"]:
                pieces.append(st.feed(step["text"][i:i + n]))
                i += n
            pieces.append(st.feed(step["text"][i:]))
            pieces.append(st.flush())
            step["expect"] = "".join(pieces)
            assert step["expect"] == session.restore(step["text"], step.get("reveal", False))
        elif op == "resolve":
            try:
                r = session.resolve_args(step["args"], Sink(**step["sink"]))
                step["expect"] = {"args": r.args}
            except HandleRefused as exc:
                step["expect"] = {"refused": exc.reason}
        elif op == "egress":
            step["expect"] = sorted({lk.type for lk in session.check_egress(step["payload"])})
        elif op == "mask_messages":
            msgs, notes = session.mask_messages(step["messages"])
            step["expect"] = {"messages": msgs, "notes": notes}
        else:
            raise ValueError(op)
        out.append(step)
    return out


MAIL = ("From: Dana Reyes <dana.reyes@gmail.com>\nHi Sam,\n\nCan we move Thursday's call to March 12, 2026? "
        "Call me at (617) 555-0142.\nYour Acme verification code is 482913. It expires in 10 minutes.\n\nThanks,\nDana")


def scenario_vectors():
    scenarios = []

    def scenario(name, profile, steps, seed=bytes(32), now=NOW, known=None):
        s = Session(profile, Vault(seed=seed, created=now), clock=lambda: now, known=known or {})
        recorded = run_steps(s, steps)
        scenarios.append({"name": name, "profile": profile, "seed": seed.hex(), "now": now,
                          "known": known or {}, "steps": recorded})

    def mail_checks(steps):
        masked = steps[0]["expect"]["text"]
        for real in ["Dana", "Reyes", "Sam", "dana.reyes", "617", "482913", "March 12"]:
            assert real not in masked, real
        assert "{{OTP_1}}" in masked and "Thursday" in masked and ".example>" in masked
        assert steps[1]["expect"] == MAIL  # restore with reveal gives back the exact input

    scenario("email reply with a code", "draft_reply", [
        {"op": "mask", "text": MAIL, "source": {"sender": "no-reply@acme.com"}},
        {"op": "restore", "text": "__MASKED__", "reveal": True},
        {"op": "restore", "text": "Sounds good {{OTP_1}} [PERSON_9]"},
        {"op": "resolve", "args": {"field": "#otp", "text": "{{OTP_1}}"}, "sink": {"tool": "type", "site": "https://evil.example"}},
        {"op": "resolve", "args": {"field": "#otp", "text": "{{OTP_1}}"}, "sink": {"tool": "type", "site": "https://login.acme.com"}},
        {"op": "resolve", "args": {"text": "{{OTP_1}}"}, "sink": {"tool": "type", "site": "https://login.acme.com"}},
        {"op": "egress", "payload": "__MASKED__"},
        {"op": "egress", "payload": "__MASKED__ Dana"},
    ])

    scenario("schedule keeps dates, strict shifts them", "schedule", [
        {"op": "mask", "text": "Meet Priya Raman on 2026-03-12 and again on March 19, 2026 at 221 Baker Street."},
        {"op": "mask", "text": "Priya said 3/26/2026 works; ping priya.raman@acme.co.uk"},
    ])
    scenario("strict profile, everything", "strict", [
        {"op": "mask", "text": "Hi Omar,\nI will meet Omar Haddad and Lena Novak on 2026-03-12 (Thu). Card 4242 4242 "
                               "4242 4242, IBAN GB82 WEST 1234 5698 7654 32, SSN 123-45-6789, server 10.0.12.7, "
                               "https://docs.acme.com/r/9921xq?u=omar, Northwind Traders Inc., $1,234.50"},
        {"op": "restore", "text": "__MASKED__", "reveal": True},
        {"op": "stream", "text": "__MASKED__", "chunks": [1, 2, 3, 5, 8, 13, 21, 34, 55]},
        {"op": "mask", "text": "OMAR HADDAD replied; Lena too."},
    ])
    scenario("training data across documents", "training_data", [
        {"op": "mask", "text": "Patient contact: Elena Ortiz, elena.ortiz@example.org, +1 (415) 555-0199."},
        {"op": "mask", "text": "Follow-up for Elena Ortiz on 2026-04-02; billed $480.00."},
        {"op": "mask", "text": "password: Tr0ub4dor&3 and key sk-proj-abcdefghijklmnopqrstuvwx123"},
    ])
    scenario("egress reads bare JSON values and ignores stopword name parts", "training_data", [
        {"op": "mask", "text": "card 4242 4242 4242 4242 for May Chen"},
        {"op": "egress", "payload": "4242424242424242"},
        {"op": "egress", "payload": "[4242424242424242]"},
        {"op": "egress", "payload": "see you May 5"},
        {"op": "egress", "payload": "Chen said hi"},
    ], known={"PERSON": ["May Chen"]})
    scenario("logs use stable tokens", "logs", [
        {"op": "mask", "text": "2026-11-05 login failed for dana@acme.com from 10.0.12.7"},
        {"op": "mask", "text": "2026-11-05 login ok for DANA@ACME.COM"},
        {"op": "restore", "text": "__MASKED__"},
    ])
    scenario("known contacts and chat messages", "contacts", [
        {"op": "mask_messages", "messages": [
            {"role": "system", "content": "You help with email."},
            {"role": "user", "content": [{"type": "text", "text": "Text Iris at +44 7700 900123, code 5521 is your PIN"}]},
            {"role": "assistant", "tool_calls": [{"id": "c1", "type": "function", "function": {
                "name": "send_sms", "arguments": "{\"to\":\"+44 7700 900123\",\"body\":\"hi Iris\"}"}}]},
            {"role": "tool", "tool_call_id": "c1", "content": "sent to +44 7700 900123"},
        ]},
    ], known={"PERSON": ["Iris"]})

    # replace the __MASKED__ placeholder with the previous mask output, then record again so expectations match
    for sc in scenarios:
        last = None
        for st in sc["steps"]:
            for key in ("text", "payload"):
                if isinstance(st.get(key), str) and "__MASKED__" in st[key]:
                    st[key] = st[key].replace("__MASKED__", last)
            if st["op"] == "mask":
                last = st["expect"]["text"]
        s = Session(sc["profile"], Vault(seed=bytes.fromhex(sc["seed"]), created=sc["now"]),
                    clock=lambda: sc["now"], known=sc["known"])
        fresh = run_steps(s, [{k: v for k, v in st.items() if k != "expect"} for st in sc["steps"]])
        sc["steps"] = fresh
    mail = scenarios[0]["steps"]
    mail_checks(mail)
    assert mail[3]["expect"] == {"refused": "bound to a different site"}
    assert mail[4]["expect"] == {"args": {"field": "#otp", "text": "482913"}}
    assert mail[5]["expect"] == {"refused": "already used"}
    assert mail[6]["expect"] == [] and "PERSON" in mail[7]["expect"]
    eg = next(sc for sc in scenarios if sc["name"].startswith("egress reads"))["steps"]
    assert [st["expect"] for st in eg[1:]] == [["CARD"], ["CARD"], [], ["PERSON"]]
    strict = scenarios[2]["steps"]
    assert strict[1]["expect"] == strict[0]["text"]
    write("scenarios", {"description": "Masking scenarios with fixed seeds and clocks (spec 6-10). Each step's "
                                       "expect is what a conforming SDK must produce, byte for byte.",
                        "scenarios": scenarios})


def receipt_vectors():
    signer = Signer.from_seed(bytes(range(32)))
    body = {"opn": "0.1", "type": "egress", "session": "s1", "seq": 1, "iat": NOW, "prev": None,
            "dest": "api.example.com", "payload": digest(b"hello"), "policy": load_profile("strict").digest,
            "stand_ins": {"PERSON": 2}, "check": {"known_values": 3, "found": 0}, "detectors": ["rules@1", "known@1"]}
    token = signer.sign(body, "opn-egress+jws")
    pub_raw = signer.public_key.public_bytes_raw()
    write("receipts", {
        "description": "Egress receipt signing (spec 11.2). Ed25519 is deterministic, so the token is exact.",
        "private_key_seed": bytes(range(32)).hex(), "public_key": pub_raw.hex(), "kid": signer.kid,
        "canonical_body": canonical(body).decode(), "body": body, "token": token,
        "payload_digest_of_hello": digest(b"hello"),
    })


if __name__ == "__main__":
    checks_vectors()
    drbg_vectors()
    ff1_vectors()
    detect_vectors()
    policy_vectors()
    scenario_vectors()
    receipt_vectors()
    print("vectors written to", OUT)
