"""Property-based fuzzing of every surface that reads untrusted input.

Detection, mask and restore, streaming restore, handle filling (resolve_args with hostile arguments and sinks), the
egress check, sensitive-reference recognition, verify_log on damaged logs, canonical JSON, and the gateway that the
local proxy and the LiteLLM guardrail share. Each property says: no exception but the library's own, and the
round-trips hold. Runs are seeded (derandomize) so CI is repeatable; OPN_FUZZ_EXAMPLES raises the budget for a longer
local run, for example OPN_FUZZ_EXAMPLES=5000 python -m pytest tests/test_fuzz.py.
"""

from __future__ import annotations

import json
import os
import random
import shutil
import subprocess
from pathlib import Path

import pytest

pytest.importorskip("hypothesis")

from hypothesis import HealthCheck, assume, given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from open_pseudonym import (  # noqa: E402
    EgressLog, HandleRefused, RefusedData, Session, Signer, Sink, Source, Vault, sref_regions, verify_log,
)
from open_pseudonym.gateway import Gateway, GatewayConfig  # noqa: E402
from open_pseudonym.jcs import canonical, canonical_args  # noqa: E402

EXAMPLES = int(os.environ.get("OPN_FUZZ_EXAMPLES", "60"))
FUZZ = settings(max_examples=EXAMPLES, derandomize=True, deadline=None, database=None,
                suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large,
                                       HealthCheck.function_scoped_fixture])
NOW = 1793836800
PROFILES = ["strict", "draft_reply", "browse_and_fill", "summarize", "secrets_only"]

# Pieces that detection acts on, so random text is full of values to mask, plus noise around them
PIECES = [
    "Dana Reyes", "Priya Raman", "Omar Haddad", "dana.reyes@gmail.com", "priya@acme.co.uk", "(617) 555-0142",
    "+44 20 7946 0958", "4242 4242 4242 4242", "4111111111111111", "221 Baker Street, Apt 4", "March 12, 2026",
    "2026-04-02", "https://meet.acme.com/r/9921xq", "Northwind Traders Inc.", "code is 482913", "Password: Tr0ub4dor&3",
    "IBAN DE89 3704 0044 0532 0130 00", "SSN 123-45-6789", "Boise", "Hi Sam,", "\n", " ", ", ", ".", "{{OTP_1}}",
    "⟦", "⟧", "[EMAIL_1]", "@", "...", " ", "José Núñez", "\U0001f600", "\t",
]
noise = st.text(alphabet=st.characters(codec="utf-8"), max_size=12)
texts = st.lists(st.one_of(st.sampled_from(PIECES), noise), max_size=14).map("".join)
# Real text puts a space or a mark between two values. Glued ones ("555-0142Dana Reyes", two phone numbers with
# nothing between) are a known limit of restore, which needs a word boundary to find a stand-in
SEPS = [" ", "\n", ", ", ". ", " (", ") ", ": ", "; ", " - ", "\t"]
words = st.text(alphabet=st.characters(codec="utf-8", exclude_characters="\u27e6\u27e7"), max_size=10)
# Input that already holds our own syntax ({{OTP_1}}, [EMAIL_1]) collides with the stand-ins minted for it; that is a
# spec question (section 9), so the round-trip properties leave it out and the crash properties keep it in
REAL_PIECES = [p for p in PIECES if p not in ("{{OTP_1}}", "[EMAIL_1]")]
separated = st.lists(st.tuples(st.one_of(st.sampled_from(REAL_PIECES), words), st.sampled_from(SEPS)),
                     max_size=10).map(lambda parts: "".join(p + sep for p, sep in parts))
any_text = st.one_of(texts, st.text(max_size=200))
json_scalars = st.one_of(st.none(), st.booleans(), st.integers(), st.floats(allow_nan=False), any_text)
json_values = st.recursive(json_scalars, lambda c: st.one_of(st.lists(c, max_size=4),
                                                             st.dictionaries(any_text, c, max_size=4)), max_leaves=20)
hosts = st.one_of(st.sampled_from(["acme.com", "https://acme.com/2fa", "login.acme.com", "github.io", "", ".", "..",
                                   "acme.com.", "[::1]:80", "x@acme.com", "https://u:p@acme.com:8443/x?y#z"]),
                  st.text(max_size=40))


def session(profile="strict", **kw) -> Session:
    return Session(profile, Vault(seed=bytes(32), created=NOW), clock=lambda: NOW, **kw)


def mask_or_refuse(s: Session, text: str, source=None):
    try:
        return s.mask(text, source)
    except RefusedData:
        return None


@FUZZ
@given(text=any_text, profile=st.sampled_from(PROFILES))
def test_detect_spans_are_inside_the_text_and_mask_never_crashes(text, profile):
    s = session(profile)
    for span in s.detect(text):
        assert 0 <= span.start < span.end <= len(text)
        assert text[span.start:span.end] == span.text
    mask_or_refuse(s, text, Source(sender="no-reply@acme.com"))


@FUZZ
@given(text=separated, profile=st.sampled_from(["strict", "draft_reply", "browse_and_fill"]))
def test_mask_then_restore_gives_the_original(text, profile):
    s = session(profile)
    m = mask_or_refuse(s, text, Source(sender="no-reply@acme.com"))
    assume(m is not None)
    assert s.restore(m.text, reveal_handles=True) == text


@FUZZ
@given(text=separated, cuts=st.lists(st.integers(1, 12), min_size=1, max_size=40))
def test_streaming_restore_matches_whole_restore(text, cuts):
    s = session("strict")
    m = mask_or_refuse(s, text)
    assume(m is not None)
    masked = m.text + " " + m.text  # a stand-in may be cut anywhere, more than once
    st_ = s.stream()
    out, i, k = [], 0, 0
    while i < len(masked):
        n = cuts[k % len(cuts)]
        out.append(st_.feed(masked[i:i + n]))
        i, k = i + n, k + 1
    out.append(st_.flush())
    assert "".join(out) == s.restore(masked)


@FUZZ
@given(text=any_text)
def test_restore_and_stream_never_crash_on_model_output(text):
    s = session("draft_reply")
    s.mask("From: Dana Reyes <dana.reyes@gmail.com>, (617) 555-0142, code 482913", Source(sender="a@acme.com"))
    s.restore(text)
    s.restore(text, reveal_handles=True)
    s.unknown_stand_ins(text)
    st_ = s.stream()
    st_.feed(text)
    st_.flush()


@FUZZ
@given(args=st.one_of(json_values, any_text, st.sampled_from(['{"t": "{{OTP_1}}"', '["{{OTP_1}}"]', "{{OTP_1}}",
                                                               '{"t": "{{OTP_9}}"}', '{"a": "\\ud800 {{OTP_1}}"}'])),
       tool=st.one_of(st.none(), any_text), site=st.one_of(st.none(), hosts),
       answer=st.sampled_from([None, True, False, "yes", {"allowed": True}, 1, []]))
def test_resolve_args_refuses_only_with_handle_refused(args, tool, site, answer):
    approve = None if answer is None else (lambda h, d, sink: answer)
    s = session("browse_and_fill", approve=approve)
    s.mask("Your Acme verification code is 482913. It expires in 10 minutes.", Source(sender="no-reply@acme.com"))
    if isinstance(args, (dict, list)):
        args = {"x": args, "code": "{{OTP_1}}"}
    try:
        s.resolve_args(args, Sink(tool, site))
    except HandleRefused as exc:
        assert exc.code
    except (TypeError, ValueError) as exc:  # a bad approval answer is the caller's bug, and says so
        assert answer is not None and not isinstance(answer, bool), exc


@FUZZ
@given(payload=st.one_of(any_text, st.binary(max_size=200), json_values.map(json.dumps)))
def test_egress_check_never_crashes_and_finds_real_values(payload):
    s = session("strict")
    s.mask("From: Dana Reyes <dana.reyes@gmail.com>, (617) 555-0142")
    s.check_egress(payload)
    if isinstance(payload, str):
        assert s.check_egress(payload + " dana.reyes@gmail.com")


@FUZZ
@given(text=any_text)
def test_sref_regions_are_sorted_and_inside(text):
    regions = sref_regions(text)
    last = 0
    for a, b in regions:
        assert last <= a < b <= len(text)
        last = b


@FUZZ
@given(data=st.data())
def test_verify_log_reports_damage_and_never_raises(tmp_path_factory, data):
    folder = tmp_path_factory.mktemp("log")
    signer = Signer.from_seed(bytes(range(32)))
    s = session("strict")
    log = EgressLog(folder, signer)
    for text in ["Dana Reyes wrote", "and (617) 555-0142", "fine"]:
        s.record_egress(log, json.dumps({"messages": [{"content": s.mask(text).text}]}).encode(), "api.example.com")
    good = verify_log(folder, signer.public_key, s.vault)
    assert good["problems"] == []
    path = folder / "receipts.jsonl"
    before = path.read_bytes()
    raw = bytearray(before)
    op = data.draw(st.sampled_from(["flip", "cut", "insert", "drop_line", "swap", "dup", "payload"]))
    if op == "flip":
        i = data.draw(st.integers(0, len(raw) - 1))
        raw[i] ^= data.draw(st.integers(1, 255))
    elif op == "cut":
        raw = raw[:data.draw(st.integers(0, len(raw) - 1))]
    elif op == "insert":
        i = data.draw(st.integers(0, len(raw)))
        raw[i:i] = data.draw(st.binary(min_size=1, max_size=20))
    elif op == "payload":
        pfile = folder / "payloads" / "000002.bin"
        pfile.write_bytes(pfile.read_bytes() + data.draw(st.binary(min_size=1, max_size=8)))
    else:
        lines = before.split(b"\n")[:-1]
        if op == "drop_line":
            del lines[data.draw(st.integers(0, len(lines) - 1))]
        elif op == "swap":
            lines[0], lines[1] = lines[1], lines[0]
        else:
            lines.insert(1, lines[1])
        raw = bytearray(b"\n".join(lines) + b"\n")
    path.write_bytes(bytes(raw))
    report = verify_log(folder, signer.public_key, s.vault, expect_count=3, expect_last=good["last"])

    def records(b: bytes) -> list[str]:  # read the way verify_log reads (str.splitlines also splits on \v and \u2028)
        return [ln for ln in b.decode("utf-8", "replace").splitlines() if ln.strip()]

    if op == "payload" or records(bytes(raw)) != records(before):
        assert report["problems"], (op, bytes(raw))
    shutil.rmtree(folder)


@FUZZ
@given(value=json_values)
def test_canonical_args_is_idempotent(value):
    try:
        once = canonical_args(value)
    except (TypeError, ValueError, OverflowError):  # a lone surrogate or a number JSON cannot hold: no canonical form
        return
    assert canonical_args(json.loads(once)) == once


@FUZZ
@given(value=st.recursive(st.one_of(st.none(), st.booleans(), st.integers(-(2**53), 2**53), st.text(max_size=20)),
                          lambda c: st.one_of(st.lists(c, max_size=4), st.dictionaries(st.text(max_size=8), c,
                                                                                       max_size=4)), max_leaves=20))
def test_canonical_is_idempotent(value):
    try:
        once = canonical(value)
    except UnicodeEncodeError:  # a lone surrogate is not text
        return
    assert canonical(json.loads(once)) == once


# The gateway: request bodies from the caller, responses from the model provider

@FUZZ
@given(body=st.dictionaries(st.sampled_from(["model", "messages", "input", "system", "instructions", "tools",
                                             "metadata", "stream", "x"]), json_values, max_size=5),
       sender=st.one_of(st.none(), hosts))
def test_gateway_masks_any_body_or_refuses_it(body, sender):
    s = session("strict")
    source = Source(sender=sender) if sender else None
    try:
        out = Gateway.mask_body(s, body, source)
        json.dumps(out)
    except (RefusedData, UnicodeError, RecursionError, TypeError, ValueError):
        pass  # the guardrail turns each of these into a 400 refusal; nothing is forwarded


@FUZZ
@given(data=json_values, shape=st.sampled_from(["chat", "anthropic", "responses"]))
def test_gateway_restores_any_response_shape_without_crashing(data, shape):
    g = Gateway(GatewayConfig(profile="strict", fill_tools={"type": "acme.com"}))
    s = g.session_for("sid", g.base_policy)
    s.mask("From: Dana Reyes <dana.reyes@gmail.com>, code 482913", Source(sender="no-reply@acme.com"))
    wrap = {"chat": lambda d: {"choices": d}, "anthropic": lambda d: {"content": d},
            "responses": lambda d: {"output": d, "output_text": d}}[shape]
    body = wrap(data if isinstance(data, list) else [data])
    getattr(g, f"restore_{shape}")(s, body)


# Python and TypeScript agree on canonical JSON

NODE = shutil.which("node")
TS = Path(__file__).resolve().parents[2] / "typescript"


def _node_ok() -> bool:
    if not NODE:
        return False
    out = subprocess.run([NODE, "-p", "process.versions.node"], capture_output=True, text=True).stdout.strip()
    major, minor = (int(x) for x in out.split(".")[:2])
    return (major, minor) >= (23, 6)


@pytest.mark.skipif(not _node_ok(), reason="needs Node 23.6+ to run the TypeScript sources")
def test_python_and_typescript_canonical_json_agree(tmp_path):
    rng = random.Random(8785)

    def value(depth=0):
        r = rng.random()
        if depth > 3 or r < 0.35:
            return rng.choice([
                None, True, False, rng.randint(-(2**53), 2**53), rng.randint(-1000, 1000), rng.uniform(-1e6, 1e6),
                rng.choice([0.1, 1e21, 1e-7, 5e-324, 1.7976931348623157e308, 123456789012345680000.0, -0.0, 2**60]),
                "".join(rng.choice("aZ\"\\\n\t\x00\x1f\x7fé \U0001f600 ") for _ in range(rng.randint(0, 8))),
            ])
        if r < 0.65:
            return [value(depth + 1) for _ in range(rng.randint(0, 4))]
        return {"".join(rng.choice("abZé\U0001f600ﬁ") for _ in range(rng.randint(0, 3))): value(depth + 1)
                for _ in range(rng.randint(0, 4))}

    corpus = [value() for _ in range(max(300, EXAMPLES * 5))]
    src = tmp_path / "corpus.json"
    src.write_text(json.dumps(corpus), encoding="utf-8")
    script = (f"import {{ canonicalArgs }} from {json.dumps((TS / 'src' / 'jcs.ts').as_uri())};"
              "import * as fs from 'node:fs';"
              "const c = JSON.parse(fs.readFileSync(process.argv[1], 'utf8'));"
              "process.stdout.write(JSON.stringify(c.map((v) => canonicalArgs(v).toString('utf8'))));")
    out = subprocess.run([NODE, "--input-type=module", "-e", script, str(src)], capture_output=True, text=True,
                         check=True, encoding="utf-8")
    theirs = json.loads(out.stdout)
    # JSON.parse reads every number as a double; read them the same way here so both sides see the same values
    ours = [canonical_args(v).decode("utf-8") for v in json.loads(src.read_text(encoding="utf-8"),
                                                                 parse_int=lambda s: float(s) if abs(int(s)) > 2**53
                                                                 else int(s))]
    assert ours == theirs
