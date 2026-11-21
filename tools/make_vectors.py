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

from open_pseudonym import HandleRefused, Session, Signer, Sink, Source, Vault, load_profile  # noqa: E402
from open_pseudonym import checks  # noqa: E402
from open_pseudonym.drbg import Drbg  # noqa: E402
from open_pseudonym.fpe import FF1  # noqa: E402
from open_pseudonym.jcs import canonical, digest  # noqa: E402
from open_pseudonym.conformance import run_checkpoint_case, run_release_case, run_shape_case  # noqa: E402
import tempfile  # noqa: E402

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
     [["LOCATION", "New York"], ["PERSON", "Priya Raman"], ["ADDRESS", "221 Baker Street, Apt 4"],
      ["MONEY", "$1,234.50"]]),
    ("strict", "SSN 123-45-6789, routing number 021000021, tracking 123456789, see https://acme.com/a?id=7.",
     [["SSN", "123-45-6789"], ["ROUTING", "021000021"], ["ID", "123456789"], ["URL", "https://acme.com/a?id=7"]]),
    ("strict", "signed with Northwind Traders Inc. on 2026-02-30 and 12 Mar 2026",
     [["ORG", "Northwind Traders Inc."], ["DATE", "12 Mar 2026"]]),
    ("strict", 'hey Carmen, my login code was 551208. Thanks Femi Adebayo for the help!',
     [["PERSON", "Carmen"], ["OTP", "551208"], ["PERSON", "Femi Adebayo"]]),
    ("strict", '{"results": [{"name": "Ana Whitfield", "role": "approver"}, {"requester": "Dev Malhotra"}]}',
     [["PERSON", "Ana Whitfield"], ["PERSON", "Dev Malhotra"]]),
    ("strict", "Please pay Bilal Okonkwo back. Invoice to Grace Lindholm, 48 Harbor Road.",
     [["PERSON", "Bilal Okonkwo"], ["PERSON", "Grace Lindholm"], ["ADDRESS", "48 Harbor Road"]]),
    # 0.2: names without a cue, from the given-name list, in several orders and alphabets
    ("strict", "I met Priya yesterday; Sam Patel and Wei Zhang joined. Daniel J. Smith signed.",
     [["PERSON", "Priya"], ["PERSON", "Sam Patel"], ["PERSON", "Wei Zhang"], ["PERSON", "Daniel J. Smith"]]),
    ("strict", "Notes from Nguyễn Văn An and Zhang Wei: Will you join? May 5 works.",
     [["PERSON", "Nguyễn Văn An"], ["PERSON", "Zhang Wei"], ["DATE", "May 5"]]),
    ("strict", "Ms. Reyes called. Dana Reyes wants a refund.", [["PERSON", "Reyes"], ["PERSON", "Dana Reyes"]]),
    ("strict", "Morgan Stanley hired Morgan Lee at Bank of America.",
     [["ORG", "Morgan Stanley"], ["PERSON", "Morgan Lee"], ["ORG", "Bank of America"]]),
    # 0.2: records, places, postcodes, handles
    ("strict", "Patient MRN 448812 was seen at St. Mary's Hospital in Boise, Idaho; order #A12345 for CUST-00921 "
               "(ISO-8601, CVE-2024-12345).",
     [["ID", "448812"], ["ORG", "St. Mary's Hospital"], ["LOCATION", "Boise"], ["LOCATION", "Idaho"],
      ["ID", "A12345"], ["ID", "CUST-00921"]]),
    ("strict", "She lives in Austin, works with Austin Lee, and moved to Smalltown, MT 59801.",
     [["LOCATION", "Austin"], ["PERSON", "Austin Lee"], ["LOCATION", "Smalltown, MT"], ["ADDRESS", "59801"]]),
    ("strict", "Offices in London NW1 6XE and Ottawa K1A 0B1.",
     [["LOCATION", "London"], ["ADDRESS", "NW1 6XE"], ["LOCATION", "Ottawa"], ["ADDRESS", "K1A 0B1"]]),
    ("strict", "Ping @dana_r or <@U12345>; the decorator @property stays. Email dana@acme.com.",
     [["USERNAME", "@dana_r"], ["USERNAME", "@U12345"], ["EMAIL", "dana@acme.com"]]),
    ("strict", "Hola María, see https://linkedin.com/in/dana-reyes today.",
     [["PERSON", "María"], ["URL", "https://linkedin.com/in/dana-reyes"]]),
    # sensitive references (spec 10.5) are opaque: nothing fully inside one is a value, even digits that look like a
    # card, but a value that reaches outside one, or the same words outside, still is
    ("strict", "card sref:contact:42424242424242424242424242 and \u27e6sref:account:01JCK7KF9X4Y3M4N6Q6YB2D8P0\u27e7 and 4242 4242 4242 4242",
     [["CARD", "4242 4242 4242 4242"]]),
    ("strict", "ssn sref:ssn:12345678901234567890123456 phone \u27e6sref:phone:16175550142617555014261755\u27e7 ok", []),
    ("strict", "see sref:contact:01JCK7KF9X4Y3M4N6Q6YB2D8P0.dana.reyes@gmail.com now",
     [["EMAIL", "01JCK7KF9X4Y3M4N6Q6YB2D8P0.dana.reyes@gmail.com"]]),
    ("strict", "sref:k:ABCDEFGHIJKLMNOPQRST-4111 1111 1111 1111", [["CARD", "4111 1111 1111 1111"]]),
    ("strict", "sref:x:danareyes_personal_2024@gmail.com", [["EMAIL", "danareyes_personal_2024@gmail.com"]]),
    ("strict", "sref:contact:01JCK7KF9X4Y3M4N6Q6YB2D8P0 and 4111 1111 1111 1111.", [["CARD", "4111 1111 1111 1111"]]),
    # only the ULID form is a reference: a looser id would be a place for a value to hide
    ("strict", "card sref:contact:4242424242424242abcd", [["CARD", "4242424242424242"]]),
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
        elif op == "resolve_report":
            step["expect"] = {"report": session.resolve_args(step["args"], Sink(**step["sink"])).report}
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
        {"op": "resolve", "args": {"text": "{{OTP_1}}"}, "sink": {"tool": "type", "site": "https://login.acme.com"}},
        {"op": "resolve", "args": {"field": "#otp", "text": "{{OTP_1}}"}, "sink": {"tool": "type", "site": "https://acme.com/login"}},
        {"op": "resolve", "args": {"text": "{{OTP_1}}"}, "sink": {"tool": "type", "site": "https://acme.com/login"}},
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
        {"op": "egress", "payload": "see you in May"},
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

    scenario("names are hidden whole", "strict", [
        {"op": "mask", "text": "Ms. Reyes called. Dana Reyes wants a refund; D. Reyes signed. Met Zorblax Reyes too."},
        {"op": "restore", "text": "__MASKED__", "reveal": True},
        {"op": "egress", "payload": "__MASKED__"},
        {"op": "egress", "payload": "__MASKED__ Dana"},
    ])
    scenario("the contacts level keeps names visible", "contacts", [
        {"op": "mask", "text": "email dana.reyes@acme.com and tell Dana hi"},
        {"op": "egress", "payload": "__MASKED__"},
    ])
    scenario("dates keep holidays and ages", "strict", [
        {"op": "mask", "text": "On Christmas Day, December 25, 2026, we close. I was born March 3, 1990, so I am 36. "
                               "We meet on March 12, 2026 and again on November 30, 2026."},
        {"op": "restore", "text": "__MASKED__", "reveal": True},
    ])
    scenario("places, postcodes, handles, records and companies", "strict", [
        {"op": "mask", "text": "I live at 221B Baker Street, London NW1 6XE and work at Acme Corp in Seattle; Acme "
                               "pays well. Profile: https://linkedin.com/in/dana-reyes or @dana_r. Order #A12345, "
                               "CUST-00921, in Boise, Idaho."},
        {"op": "restore", "text": "__MASKED__", "reveal": True},
        {"op": "egress", "payload": "__MASKED__"},
    ])
    scenario("summaries describe places coarsely", "summarize", [
        {"op": "mask", "text": "She moved from Boise, Idaho to Kenya; ZIP 02115. Later: Smalltown, MT and London NW1 6XE."},
    ])

    # Sensitive references (spec 10.5): a reference is never masked, restored, filled or reported, even when a fake's
    # digits sit inside it. The digits of the fake phone number are only known once the seed has spoken, so a twin
    # session finds them first.
    sref_bare, sref_ref = "sref:contact:42424242424242424242424242", "\u27e6sref:account:01JCK7KF9X4Y3M4N6Q6YB2D8P0\u27e7"
    sref_text = f"Call (617) 555-0142 about {sref_bare} and {sref_ref}."
    twin = Session("strict", Vault(seed=bytes(32), created=NOW), clock=lambda: NOW)
    twin.mask(sref_text)
    fake_digits = "".join(c for c in next(e.stand_in for e in twin.vault.entries if e.type == "PHONE") if c.isdigit())
    inside = f"sref:contact:ABCDEFGH{fake_digits}JKMNPQRS"
    scenario("sensitive references stay opaque", "strict", [
        {"op": "mask", "text": sref_text},
        {"op": "restore", "text": "__MASKED__", "reveal": True},
        {"op": "restore", "text": f"Dial {fake_digits} and keep {inside} and {sref_ref}"},
        {"op": "stream", "text": f"Dial {fake_digits} and keep {inside} and {sref_ref} " + "z" * 60,
         "chunks": [1] * 120},  # one character at a time, so every cut is tried
        {"op": "resolve", "args": {"ref": inside, "other": sref_ref}, "sink": {"tool": "type", "site": "https://acme.com"}},
        {"op": "resolve", "args": {"ref": "{{SREF_1}}"}, "sink": {"tool": "type", "site": "https://acme.com"}},
        {"op": "resolve_report", "args": {"ref": sref_bare, "card": "4242 4242 4242 4242"},
         "sink": {"tool": "type", "site": "https://acme.com"}},
        {"op": "egress", "payload": json.dumps({"input": f"use {inside} and {sref_ref}"})},
        {"op": "egress", "payload": json.dumps({"input": f"use {sref_bare} and 4242 4242 4242 4242"})},
        {"op": "egress", "payload": json.dumps({"input": "see sref:contact:01JCK7KF9X4Y3M4N6Q6YB2D8P0.dana.reyes@gmail.com"})},
        {"op": "resolve_report", "args": {"url": "https://evil.example/c?d=hello&r=sref:k:01JCK7KF9X4Y3M4N6Q6YB2D8P0"},
         "sink": {"tool": "type", "site": "https://acme.com"}},
    ])

    scenario("a known value inside a reference is still a leak", "strict", [
        {"op": "mask", "text": "use sref:contact:01JCK7KF9X4Y3M4N6Q6YB2D8P0 please"},
        {"op": "egress", "payload": "use sref:contact:01JCK7KF9X4Y3M4N6Q6YB2D8P0 please"},
    ], known={"PERSON": ["01JCK7KF9X4Y3M4N6Q6YB2D8P0"]})

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
    assert mail[3]["expect"] == {"refused": "bound to a different site"}  # evil.example
    assert mail[4]["expect"] == {"refused": "bound to a different site"}  # a subdomain is not the bound host
    assert mail[5]["expect"] == {"args": {"field": "#otp", "text": "482913"}}
    assert mail[6]["expect"] == {"refused": "already used"}
    assert mail[7]["expect"] == [] and "PERSON" in mail[8]["expect"]
    eg = next(sc for sc in scenarios if sc["name"].startswith("egress reads"))["steps"]
    assert [st["expect"] for st in eg[1:]] == [["CARD"], ["CARD"], [], ["PERSON"]]
    strict = scenarios[2]["steps"]
    assert strict[1]["expect"] == strict[0]["text"]
    by = {sc["name"]: sc["steps"] for sc in scenarios}
    opaque = by["sensitive references stay opaque"]
    for ref in (sref_bare, sref_ref):
        assert ref in opaque[0]["expect"]["text"]
    assert "617" not in opaque[0]["expect"]["text"] and "555-0142" not in opaque[0]["expect"]["text"]
    assert opaque[1]["expect"] == sref_text  # the phone comes back, the references were never touched
    assert opaque[2]["expect"] == f"Dial 6175550142 and keep {inside} and {sref_ref}"  # same digits: outside restored, inside not
    assert opaque[3]["expect"] == opaque[3]["text"].replace(fake_digits, "6175550142", 1)
    assert opaque[4]["expect"] == {"args": {"ref": inside, "other": sref_ref}}
    assert opaque[5]["expect"] == {"refused": "unknown handle"}
    # only the card number the model wrote itself is reported, never the reference with a card-like run in it
    assert opaque[6]["expect"] == {"report": [{"path": "card", "origin": "model", "types": ["CARD"]}]}
    known = by["a known value inside a reference is still a leak"]
    assert known[0]["expect"]["text"] == known[0]["text"] and known[1]["expect"] == ["PERSON"]
    assert opaque[7]["expect"] == [] and opaque[8]["expect"] == ["CARD"] and opaque[9]["expect"] == ["EMAIL"]
    # a reference inside a link is not an excuse: the link reaches outside it
    assert opaque[10]["expect"] == {"report": [{"path": "url", "origin": "model", "types": ["URL"]}]}
    whole = by["names are hidden whole"]
    assert "Dana" not in whole[0]["expect"]["text"] and "Zorblax" not in whole[0]["expect"]["text"]
    assert whole[1]["expect"] == whole[0]["text"] and whole[2]["expect"] == [] and "PERSON" in whole[3]["expect"]
    assert by["the contacts level keeps names visible"][1]["expect"] == []
    days = by["dates keep holidays and ages"]
    assert "Christmas Day, December 25, 2026" in days[0]["expect"]["text"] and "March 12, 2026" not in days[0]["expect"]["text"]
    assert days[1]["expect"] == days[0]["text"]
    place = by["places, postcodes, handles, records and companies"]
    for real in ["Baker", "NW1 6XE", "Acme", "Seattle", "dana-reyes", "@dana_r", "A12345", "CUST-00921", "Boise"]:
        assert real not in place[0]["expect"]["text"], real
    assert "ZZ99 " in place[0]["expect"]["text"] and place[1]["expect"] == place[0]["text"] and place[2]["expect"] == []
    summary = by["summaries describe places coarsely"][0]["expect"]["text"]
    assert "from a city, Idaho to Kenya" in summary and "021xx" in summary and "a town in Montana" in summary, summary
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


def release_vectors():
    writer = Signer.from_seed(bytes(range(32)))
    mail = "Your Acme verification code is 482913. It expires in 10 minutes."
    acme = {"sender": "no-reply@acme.com"}
    card_text = "Pay with card 4242 4242 4242 4242 on the checkout page."
    shop = {"site": "https://shop.example"}
    type_acme = {"tool": "type", "site": "https://acme.com/login"}
    zero = bytes(32).hex()
    never = ["482913", digest(b"482913"), "4242424242424242", digest(b"4242424242424242")]
    # `shown` commits to the nonce the vault keeps for the handle; a seeded vault draws it from its own generator
    twin = Session("browse_and_fill", Vault(seed=bytes.fromhex(zero), created=NOW), clock=lambda: NOW)
    twin.mask(card_text, Source(**shop))
    nonce = twin.vault.release_nonce(twin.vault.entries[0])

    def call(args):
        return digest(canonical(args))  # the arguments with the handle still in them

    def rec(seq, prev_idx, **kw):
        base = {"opn": "0.1", "type": "release", "session": "s1", "seq": seq, "prev": prev_idx, "iat": NOW}
        base.update(kw)
        return base

    def case(name, profile, text, source, approve, steps):
        return {"name": name, "profile": profile, "seed": zero, "now": NOW, "mask": {"text": text, "source": source},
                "approve": approve, "steps": steps, "never_in_records": never + [nonce]}

    a1 = {"selector": "#otp", "text": "{{OTP_1}}"}
    cases = [
        case("allowed by the binding, then used up", "browse_and_fill", mail, acme, None, [
            {"args": a1, "sink": {"tool": "type", "site": "https://evil.example"}},
            {"args": a1, "sink": type_acme},
            {"args": a1, "sink": type_acme},
        ]),
        case("an unknown handle, a wrong tool and no binding", "browse_and_fill", mail, acme, None, [
            {"args": {"t": "{{OTP_9}}"}, "sink": type_acme},
        ]),
        case("allowed by a person, who is on record with what they were shown", "browse_and_fill", card_text, shop,
             {"allowed": True, "by": "mia", "channel": "app"}, [
            {"args": {"card": "{{CARD_1}}"}, "sink": {"tool": "type", "site": "https://shop.example/pay"}},
        ]),
        case("allowed by an OAC consent", "browse_and_fill", card_text, shop,
             {"allowed": True, "ref": "jti-7f3a", "digest": digest(b"consent token")}, [
            {"args": {"card": "{{CARD_1}}"}, "sink": {"tool": "type", "site": "https://shop.example/pay"}},
        ]),
        case("a person says no", "browse_and_fill", card_text, shop, {"allowed": False, "by": "mia"}, [
            {"args": {"card": "{{CARD_1}}"}, "sink": {"tool": "type", "site": "https://shop.example/pay"}},
        ]),
        case("a rule asks and nobody is there to ask", "browse_and_fill", card_text, shop, None, [
            {"args": {"card": "{{CARD_1}}"}, "sink": {"tool": "type", "site": "https://shop.example/pay"}},
        ]),
        case("expired", "browse_and_fill", mail, acme, None, [
            {"args": a1, "sink": type_acme, "at": NOW + 600},
        ]),
        case("not bound to anything", "browse_and_fill", mail, None, None, [{"args": a1, "sink": type_acme}]),
        case("the audit comes first: no record, no fill, no use counted", "browse_and_fill", mail, acme, None, [
            {"op": "break_log"},
            {"args": a1, "sink": type_acme},
            {"op": "fix_log"},
            {"args": a1, "sink": type_acme},
        ]),
    ]
    cases += [
        case("arguments with no canonical form are refused, recorded, and cost no use", "browse_and_fill", mail, acme, None, [
            {"args_json": '{"t": "{{OTP_1}}", "x": "\\ud800"}', "sink": type_acme},
            {"args": a1, "sink": type_acme},
        ]),
        case("numbers in the arguments are written the way JavaScript writes them", "browse_and_fill", mail, acme, None, [
            {"args_json": '{"n": 12345678901234567890, "f": 1.5, "big": 1e21, "text": "{{OTP_1}}"}', "sink": type_acme},
        ]),
    ]
    shown = digest(canonical({"nonce": nonce, "description": "a Visa card ending 4242", "handle": "{{CARD_1}}",
                              "site": "shop.example", "tool": "type"}))
    wrong_site = lambda seq, prev, **kw: rec(seq, prev, handle="{{OTP_1}}", data="OTP", source="acme.com",  # noqa: E731
                                              sink={"tool": "type", "site": "evil.example"}, call=call(a1),
                                              outcome="refused", decision="deny", code="wrong_site",
                                              reason="bound to a different site", authority={"kind": "binding"},
                                              uses_left=1)
    allow_otp = lambda seq, prev: rec(seq, prev, handle="{{OTP_1}}", data="OTP", source="acme.com",  # noqa: E731
                                      sink={"tool": "type", "site": "acme.com"}, call=call(a1), outcome="released",
                                      decision="allow", authority={"kind": "binding"}, uses_left=0)
    card_sink = {"tool": "type", "site": "shop.example"}
    card_args = {"card": "{{CARD_1}}"}
    expect = [
        ([{"refused": "bound to a different site", "code": "wrong_site"}, {"args": {"selector": "#otp", "text": "482913"}},
          {"refused": "already used", "code": "used_up"}],
         [wrong_site(1, None), allow_otp(2, "$1"),
          rec(3, "$2", handle="{{OTP_1}}", data="OTP", source="acme.com", sink={"tool": "type", "site": "acme.com"},
              call=call(a1), outcome="refused", decision="deny", code="used_up", reason="already used",
              authority={"kind": "binding"}, uses_left=0)]),
        ([{"refused": "unknown handle", "code": "unknown_handle"}],
         [rec(1, None, handle="{{OTP_9}}", data=None, source=None, sink={"tool": "type", "site": "acme.com"},
              call=call({"t": "{{OTP_9}}"}), outcome="refused", decision="deny", code="unknown_handle",
              reason="unknown handle", authority={"kind": "binding"})]),
        ([{"args": {"card": "4242 4242 4242 4242"}}],
         [rec(1, None, handle="{{CARD_1}}", data="CARD", source="shop.example", sink=card_sink, call=call(card_args),
              outcome="released", decision="allow",
              authority={"kind": "person", "by": "mia", "channel": "app", "shown": shown})]),
        ([{"args": {"card": "4242 4242 4242 4242"}}],
         [rec(1, None, handle="{{CARD_1}}", data="CARD", source="shop.example", sink=card_sink, call=call(card_args),
              outcome="released", decision="allow",
              authority={"kind": "consent", "ref": "jti-7f3a", "digest": digest(b"consent token"), "shown": shown})]),
        ([{"refused": "not approved", "code": "not_approved"}],
         [rec(1, None, handle="{{CARD_1}}", data="CARD", source="shop.example", sink=card_sink, call=call(card_args),
              outcome="refused", decision="deny", code="not_approved", reason="not approved",
              authority={"kind": "person", "by": "mia", "shown": shown})]),
        ([{"refused": "needs the person's approval", "code": "needs_approval"}],
         [rec(1, None, handle="{{CARD_1}}", data="CARD", source="shop.example", sink=card_sink, call=call(card_args),
              outcome="refused", decision="deny", code="needs_approval", reason="needs the person's approval",
              authority={"kind": "policy"})]),
        ([{"refused": "expired", "code": "expired"}],
         [rec(1, None, handle="{{OTP_1}}", data="OTP", source="acme.com", sink={"tool": "type", "site": "acme.com"},
              call=call(a1), outcome="refused", decision="deny", code="expired", reason="expired",
              authority={"kind": "binding"}, uses_left=1, iat=NOW + 600)]),
        ([{"refused": "not bound to a site or tool", "code": "unbound"}],
         [rec(1, None, handle="{{OTP_1}}", data="OTP", source=None, sink={"tool": "type", "site": "acme.com"},
              call=call(a1), outcome="refused", decision="deny", code="unbound", reason="not bound to a site or tool",
              authority={"kind": "binding"}, uses_left=1)]),
        ([{"refused": "release not recorded", "code": "not_recorded"}, {"args": {"selector": "#otp", "text": "482913"}}],
         [allow_otp(1, None)]),
    ]
    big = {"n": 12345678901234567890, "f": 1.5, "big": 1e21, "text": "482913"}
    # RFC 8785 by hand: keys in order, 1e21 as 1e+21, an integer past 2^53 as the nearest double
    call_big = digest(b'{"big":1e+21,"f":1.5,"n":12345678901234567000,"text":"{{OTP_1}}"}')
    expect += [
        ([{"refused": "malformed arguments", "code": "malformed"}, {"args": {"selector": "#otp", "text": "482913"}}],
         [rec(1, "none", handle="{{OTP_1}}", data="OTP", source="acme.com", sink={"tool": "type", "site": "acme.com"},
              call=digest(b"malformed"), outcome="refused", decision="deny", code="malformed",
              reason="malformed arguments", authority={"kind": "binding"}, uses_left=1),
          allow_otp(2, "$1")]),
        ([{"args": big}],
         [rec(1, None, handle="{{OTP_1}}", data="OTP", source="acme.com", sink={"tool": "type", "site": "acme.com"},
              call=call_big, outcome="released", decision="allow", authority={"kind": "binding"}, uses_left=0)]),
    ]
    assert len(expect) == len(cases)
    for c, (results, records) in zip(cases, expect):
        # "$n" stands for the digest of record n's token, which only exists once the records are signed
        with tempfile.TemporaryDirectory() as tmp:
            got = run_release_case(c, Path(tmp))
        fixed = []
        for r in records:
            r = dict(r)
            if r["prev"] == "none":
                r["prev"] = None
            if isinstance(r["prev"], str) and r["prev"].startswith("$"):
                r["prev"] = digest(got["tokens"][int(r["prev"][1:]) - 1].encode("ascii"))
            fixed.append(r)
        assert got["results"] == results, (c["name"], got["results"])
        assert got["records"] == fixed, (c["name"], got["records"])
        assert got["report"]["problems"] == [], (c["name"], got["report"]["problems"])
        c["results"], c["records"], c["tokens"] = results, fixed, got["tokens"]
    assert cases[0]["records"][1]["uses_left"] == 0 and cases[0]["records"][0]["uses_left"] == 1
    assert all(r["authority"] for c in cases for r in c["records"])

    entry = dict(session="s1", now=NOW, handle="{{OTP_1}}", data="OTP", source="acme.com",
                 sink={"tool": "type", "site": "acme.com"}, call=digest(b"x"), decision="allow",
                 authority={"kind": "binding"})
    deny = dict(entry, decision="deny", code="wrong_site", reason="bound to a different site")
    bad = lambda f: [f"release 1: {f} is not valid"]  # noqa: E731
    shapes = [
        {"name": "a good allow", "entry": entry, "problems": []},
        {"name": "a good deny", "entry": deny, "problems": []},
        {"name": "a handle without braces", "entry": entry, "set": {"handle": "OTP_1"}, "problems": bad("handle")},
        {"name": "a data type in lower case", "entry": entry, "set": {"data": "otp"}, "problems": bad("data")},
        {"name": "a call that is not a digest", "entry": entry, "set": {"call": "sha-256:abc"}, "problems": bad("call")},
        {"name": "released but denied", "entry": entry, "set": {"outcome": "refused"},
         "problems": bad("outcome and decision")},
        {"name": "an authority the spec does not know", "entry": entry, "set": {"authority": {"kind": "model"}},
         "problems": bad("authority")},
        {"name": "a code on an allow", "entry": entry, "set": {"code": "wrong_site"},
         "problems": bad("code or reason on an allow")},
        {"name": "a negative count", "entry": entry, "set": {"uses_left": -1}, "problems": bad("uses_left")},
        {"name": "a field the spec does not list", "entry": entry, "set": {"value": "x"},
         "problems": bad("the field list")},
        {"name": "a deny with the recording code", "entry": deny, "set": {"code": "not_recorded"},
         "problems": bad("code")},
        {"name": "a deny without a reason", "entry": deny, "delete": ["reason"], "problems": bad("reason")},
        {"name": "a sink with no site field", "entry": entry, "set": {"sink": {"tool": "type"}},
         "problems": bad("sink")},
        {"name": "a shown that the vault does not recompute", "entry": entry,
         "set": {"authority": {"kind": "person", "shown": digest(b"what they saw")}},
         "profile": "browse_and_fill", "seed": zero, "now": NOW, "mask": mail,
         "problems": ["release 1: shown does not match what the vault says the approver was given"]},
        {"name": "a shown for a handle the vault does not hold", "entry": dict(entry, handle="{{OTP_7}}"),
         "set": {"authority": {"kind": "person", "shown": digest(b"what they saw")}},
         "profile": "browse_and_fill", "seed": zero, "now": NOW, "mask": mail,
         "problems": ["release 1: shown names a handle the vault does not hold"]},
        {"name": "a real value hidden in a record", "entry": entry, "set": {"authority": {"kind": "person", "by": "code 482913"}},
         "profile": "browse_and_fill", "seed": zero, "now": NOW, "mask": mail,
         "problems": ["release 1: 1 known value(s) found in the record"]},
    ]
    for sc in shapes:
        with tempfile.TemporaryDirectory() as tmp:
            assert run_shape_case(sc, Path(tmp)) == sc["problems"], sc["name"]
    write("releases", {
        "description": "Release records (spec 10.4): who allowed each secret release, written before the value is "
                       "filled. Records and tokens are exact (Ed25519 is deterministic); the expected records were "
                       "worked out by hand from the spec. `never_in_records` lists the real values and their digests "
                       "that must appear nowhere in a record.",
        "private_key_seed": bytes(range(32)).hex(), "kid": writer.kid, "cases": cases, "shapes": shapes,
    })


def checkpoint_vectors():
    plan = [("allow", None), ("deny", "wrong_site"), ("allow", None), ("allow", None), ("deny", "used_up"), ("allow", None)]
    entries = []
    for n, (decision, code) in enumerate(plan, start=1):
        e = dict(session="s1", now=NOW + n, handle="{{OTP_1}}", data="OTP", source="acme.com",
                 sink={"tool": "type", "site": "acme.com"}, call=digest(f"call {n}".encode()), decision=decision,
                 authority={"kind": "binding"})
        if code:
            e.update(code=code, reason={"wrong_site": "bound to a different site", "used_up": "already used"}[code])
        entries.append(e)
    doc = {"description": "Checkpoints (spec 11.3): a head of the chain signed by a key the writer does not hold. "
                          "Six release records, cut to `keep`, checked against the anchors listed. Expected results "
                          "were worked out by hand.",
           "private_key_seed": bytes(range(32)).hex(), "anchor_key_seed": bytes(range(32, 64)).hex(),
           "other_key_seed": bytes([9] * 32).hex(), "now": NOW, "entries": entries}
    cut4 = "anchor at seq 6: the log was cut off after seq 4"
    own = "the anchor key is the key that signs the log: a checkpoint must come from a key the writer does not hold"

    def ex(receipts, problems, proven, status, reason):
        return {"receipts": receipts, "problems": problems, "proven_to": proven, "status": status, "reason": reason}

    cases = [
        {"name": "6 records cut to 4, no anchor", "keep": 4, "anchors": [],
         "expect": ex(4, [], None, "prefix", "no_anchor")},
        {"name": "6 records cut to 4, anchor at 6", "keep": 4, "anchors": [{"seq": 6}],
         "expect": ex(4, [cut4], None, "prefix", "cut_off")},
        {"name": "6 records cut to 4, anchors at 4 and 6: the one past the end wins", "keep": 4,
         "anchors": [{"seq": 4}, {"seq": 6}], "expect": ex(4, [cut4], 4, "prefix", "cut_off")},
        {"name": "6 records cut to 4, anchor at 3", "keep": 4, "anchors": [{"seq": 3}],
         "expect": ex(4, [], 3, "prefix", "unanchored_tail")},
        {"name": "6 records cut to 4, anchors at 3 and 4", "keep": 4, "anchors": [{"seq": 3}, {"seq": 4}],
         "expect": ex(4, [], 4, "complete", None)},
        {"name": "all 6 records, anchor at 6", "keep": 6, "anchors": [{"seq": 6}],
         "expect": ex(6, [], 6, "complete", None)},
        {"name": "all 6 records, anchor at 6 and a bad one at 3", "keep": 6,
         "anchors": [{"seq": 3, "head": "other"}, {"seq": 6}],
         "expect": ex(6, ["anchor at seq 3: head does not match receipt 3: the log was changed or replaced"], 6,
                      "complete", None)},
        {"name": "an anchor signed by the writer's own key", "keep": 6, "anchors": [{"seq": 6, "signer": "writer"}],
         "anchor_key": "writer", "expect": ex(6, [own], None, "prefix", "no_anchor")},
        {"name": "an anchor from a key we were not given", "keep": 6, "anchors": [{"seq": 6, "signer": "other"}],
         "expect": ex(6, ["anchor 1: unknown key"], None, "prefix", "no_anchor")},
        {"name": "an anchor for another session", "keep": 6, "anchors": [{"seq": 6, "session": "s2"}],
         "expect": ex(6, ["anchor 1: belongs to another session"], None, "prefix", "no_anchor")},
        {"name": "anchors but no key to check them with", "keep": 6, "anchors": [{"seq": 6}], "anchor_key": None,
         "expect": ex(6, ["anchors were given without an anchor_key to check them with"], None, "prefix", "no_anchor")},
        {"name": "a cut is still caught by a count the verifier kept", "keep": 4, "anchors": [], "expect_count": 6,
         "expect": ex(4, ["expected 6 receipt(s), found 4: the log was cut or added to"], None, "prefix", "no_anchor")},
    ]
    for c in cases:
        with tempfile.TemporaryDirectory() as tmp:
            got = run_checkpoint_case(doc, c, Path(tmp))
        assert got["result"] == c["expect"], (c["name"], got["result"])
        doc["tokens"] = got["full"]
        c["anchor_tokens"] = got["tokens"]
    write("checkpoints", dict(doc, cases=cases))


if __name__ == "__main__":
    checks_vectors()
    drbg_vectors()
    ff1_vectors()
    detect_vectors()
    policy_vectors()
    scenario_vectors()
    receipt_vectors()
    release_vectors()
    checkpoint_vectors()
    print("vectors written to", OUT)
