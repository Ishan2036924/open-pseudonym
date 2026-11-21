"""Release records (spec 10.4), checkpoints (spec 11.3) and the sensitive-reference boundary (spec 10.5).

Each test here is meant to fail if the check it names is taken out; see the list in CHANGELOG.md.
"""

import base64
import hashlib
import json
import os

import pytest

from open_pseudonym import (
    Approval, EgressLog, HandleRefused, Signer, Sink, Source, make_checkpoint, sref_regions, verify_log,
)
from open_pseudonym.jcs import canonical, canonical_args, digest
from open_pseudonym.jws import verify

from conftest import NOW

OTP_MAIL = "Your Acme verification code is 482913. It expires in 10 minutes."
WRITER = Signer.from_seed(bytes(range(32)))
ANCHOR = Signer.from_seed(bytes(range(32, 64)))
ACME = Sink("type", "https://acme.com/login")


def records(folder):
    out = []
    for line in (folder / "receipts.jsonl").read_text().splitlines():
        typ = json.loads(base64.urlsafe_b64decode(line.split(".")[0] + "=="))["typ"]
        out.append(verify(line, WRITER.public_key, typ))
    return out


def with_log(make_session, tmp_path, profile="browse_and_fill", **kw):
    log = EgressLog(tmp_path, WRITER, store_payloads=False)
    s = make_session(profile, release_log=log, **kw)
    s.mask(OTP_MAIL, Source(sender="no-reply@acme.com"))
    return s, log


# Stable codes


@pytest.mark.parametrize("make_args,code,reason", [
    (lambda s: ({"t": "{{OTP_9}}"}, ACME), "unknown_handle", "unknown handle"),
    (lambda s: ({"t": "{{OTP_1}}"}, Sink("type", "https://evil.example")), "wrong_site", "bound to a different site"),
    (lambda s: ({"t": "{{OTP_1}}"}, Sink("click", "https://acme.com")), "wrong_tool", "not allowed for this tool"),
])
def test_refusals_carry_stable_codes(make_session, make_args, code, reason):
    s = make_session("browse_and_fill", approve=None)
    s.mask(OTP_MAIL, Source(sender="no-reply@acme.com"))
    s.vault.entries[0].meta["tools"] = ["type"]
    args, sink = make_args(s)
    with pytest.raises(HandleRefused) as e:
        s.resolve_args(args, sink)
    assert (e.value.code, e.value.reason) == (code, reason)
    assert str(e.value).endswith(reason)


def test_used_up_expired_unbound_and_approval_codes(make_session):
    s = make_session("browse_and_fill")
    s.mask(OTP_MAIL, Source(sender="no-reply@acme.com"))
    s.resolve_args({"t": "{{OTP_1}}"}, ACME)
    with pytest.raises(HandleRefused) as e:
        s.resolve_args({"t": "{{OTP_1}}"}, ACME)
    assert (e.value.code, e.value.reason) == ("used_up", "already used")
    now = [NOW]
    s2 = make_session("browse_and_fill", clock=lambda: now[0])
    s2.mask(OTP_MAIL, Source(sender="no-reply@acme.com"))
    now[0] += 601
    with pytest.raises(HandleRefused) as e:
        s2.resolve_args({"t": "{{OTP_1}}"}, ACME)
    assert (e.value.code, e.value.reason) == ("expired", "expired")
    s3 = make_session("browse_and_fill")
    s3.mask(OTP_MAIL)  # no source, so no binding
    with pytest.raises(HandleRefused) as e:
        s3.resolve_args({"t": "{{OTP_1}}"}, ACME)
    assert (e.value.code, e.value.reason) == ("unbound", "not bound to a site or tool")
    s4 = make_session("browse_and_fill")
    s4.mask("card 4242 4242 4242 4242", Source(site="https://shop.example"))
    with pytest.raises(HandleRefused) as e:
        s4.resolve_args({"t": "{{CARD_1}}"}, Sink("type", "https://shop.example"))
    assert (e.value.code, e.value.reason) == ("needs_approval", "needs the person's approval")
    s5 = make_session("browse_and_fill", approve=lambda h, d, k: False)
    s5.mask(OTP_MAIL, Source(sender="no-reply@acme.com"))
    with pytest.raises(HandleRefused) as e:
        s5.resolve_args({"t": "{{OTP_1}}"}, ACME)
    assert (e.value.code, e.value.reason) == ("not_approved", "not approved")


# Release records


def test_allowed_by_binding_is_recorded_before_it_is_filled(make_session, tmp_path):
    s, log = with_log(make_session, tmp_path)
    r = s.resolve_args({"selector": "#otp", "text": "{{OTP_1}}"}, ACME)
    assert r.args["text"] == "482913"
    (rec,) = records(tmp_path)
    assert rec == {
        "opn": "0.1", "type": "release", "session": s.id, "seq": 1, "prev": None, "iat": NOW, "handle": "{{OTP_1}}",
        "data": "OTP", "source": "acme.com", "sink": {"tool": "type", "site": "acme.com"},
        "call": digest(canonical({"selector": "#otp", "text": "{{OTP_1}}"})), "outcome": "released",
        "decision": "allow", "authority": {"kind": "binding"}, "uses_left": 0,
    }
    assert verify_log(tmp_path, WRITER.public_key, s.vault)["problems"] == []


def test_allowed_by_a_person_records_who_and_what_they_saw(make_session, tmp_path):
    s, _ = with_log(make_session, tmp_path, approve=lambda h, d, k: Approval(True, by="mia", channel="app"))
    s.resolve_args({"text": "{{OTP_1}}"}, ACME)
    (rec,) = records(tmp_path)
    shown = digest(canonical({"handle": "{{OTP_1}}", "description": s.vault.entries[0].meta["description"],
                              "tool": "type", "site": "acme.com"}))
    assert rec["authority"] == {"kind": "person", "by": "mia", "channel": "app", "shown": shown}


def test_a_plain_yes_still_works_and_an_oac_consent_is_recorded(make_session, tmp_path):
    s, _ = with_log(make_session, tmp_path, approve=lambda h, d, k: True)
    s.resolve_args({"text": "{{OTP_1}}"}, ACME)
    assert records(tmp_path)[0]["authority"]["kind"] == "person"
    assert set(records(tmp_path)[0]["authority"]) == {"kind", "shown"}
    consent = digest(b"the consent token")
    s2, _ = with_log(make_session, tmp_path / "b",
                     approve=lambda h, d, k: Approval(True, ref="jti-123", digest=consent))
    s2.resolve_args({"text": "{{OTP_1}}"}, ACME)
    auth = records(tmp_path / "b")[0]["authority"]
    assert (auth["kind"], auth["ref"], auth["digest"]) == ("consent", "jti-123", consent)


def test_a_bad_approval_answer_fills_nothing(make_session, tmp_path):
    s, _ = with_log(make_session, tmp_path, approve=lambda h, d, k: "yes")
    with pytest.raises(TypeError):
        s.resolve_args({"text": "{{OTP_1}}"}, ACME)
    s2, _ = with_log(make_session, tmp_path / "b", approve=lambda h, d, k: Approval(True, digest="not a digest"))
    with pytest.raises(ValueError):
        s2.resolve_args({"text": "{{OTP_1}}"}, ACME)
    assert not (tmp_path / "receipts.jsonl").exists() and not (tmp_path / "b" / "receipts.jsonl").exists()


def test_denials_are_recorded_with_their_code(make_session, tmp_path):
    s, _ = with_log(make_session, tmp_path)
    with pytest.raises(HandleRefused):
        s.resolve_args({"text": "{{OTP_1}}"}, Sink("type", "https://evil.example"))
    s.resolve_args({"text": "{{OTP_1}}"}, ACME)
    with pytest.raises(HandleRefused):
        s.resolve_args({"text": "{{OTP_1}}"}, ACME)
    got = [(r["decision"], r.get("code"), r["outcome"], r["authority"]["kind"]) for r in records(tmp_path)]
    assert got == [("deny", "wrong_site", "refused", "binding"), ("allow", None, "released", "binding"),
                   ("deny", "used_up", "refused", "binding")]
    assert records(tmp_path)[0]["reason"] == "bound to a different site"


def test_a_refused_approval_and_a_missing_approver_are_recorded(make_session, tmp_path):
    s, _ = with_log(make_session, tmp_path, approve=lambda h, d, k: Approval(False, by="mia"))
    with pytest.raises(HandleRefused):
        s.resolve_args({"text": "{{OTP_1}}"}, ACME)
    rec = records(tmp_path)[0]
    assert (rec["code"], rec["authority"]["kind"], rec["authority"]["by"]) == ("not_approved", "person", "mia")
    assert rec["authority"]["shown"].startswith("sha-256:")
    log = EgressLog(tmp_path / "b", WRITER, store_payloads=False)
    s2 = make_session("browse_and_fill", release_log=log)
    s2.mask("card 4242 4242 4242 4242", Source(site="https://shop.example"))
    with pytest.raises(HandleRefused):
        s2.resolve_args({"t": "{{CARD_1}}"}, Sink("type", "https://shop.example"))
    rec = records(tmp_path / "b")[0]
    assert (rec["code"], rec["authority"]) == ("needs_approval", {"kind": "policy"})


def test_an_unknown_handle_is_a_recorded_denial_with_no_data(make_session, tmp_path):
    s, _ = with_log(make_session, tmp_path)
    with pytest.raises(HandleRefused):
        s.resolve_args({"t": "{{OTP_9}}"}, ACME)
    rec = records(tmp_path)[0]
    assert (rec["code"], rec["data"], rec["source"], rec["uses_left"] if "uses_left" in rec else None) == (
        "unknown_handle", None, None, None)


def test_audit_comes_first_and_a_failed_write_fills_nothing(make_session, tmp_path):
    s, log = with_log(make_session, tmp_path)
    entry = s.vault.entries[0]
    os.mkdir(tmp_path / "receipts.jsonl")  # appending to a folder fails
    with pytest.raises(HandleRefused) as e:
        s.resolve_args({"text": "{{OTP_1}}"}, ACME)
    assert (e.value.code, e.value.reason) == ("not_recorded", "release not recorded")
    assert entry.meta["uses_left"] == 1 and entry.meta["sinks"] == []  # no use was counted
    os.rmdir(tmp_path / "receipts.jsonl")
    assert s.resolve_args({"text": "{{OTP_1}}"}, ACME).args == {"text": "482913"}  # still has its one use
    assert len(records(tmp_path)) == 1 and log.seq == 1


def test_several_handles_in_one_call_are_recorded_together(make_session, tmp_path):
    log = EgressLog(tmp_path, WRITER, store_payloads=False)
    s = make_session("browse_and_fill", release_log=log, approve=lambda h, d, k: True)
    s.mask(OTP_MAIL + " Password: hunter2-xyz", Source(site="https://acme.com"))
    handles = sorted({h for e in s.vault.entries if e.action == "handle" for h in [e.stand_in]})
    assert len(handles) >= 2
    s.resolve_args({"a": handles[0], "b": handles[1]}, ACME)
    recs = records(tmp_path)
    assert [r["handle"] for r in recs] == handles[:2]
    assert recs[0]["call"] == recs[1]["call"] and [r["seq"] for r in recs] == [1, 2]
    assert recs[1]["prev"] == digest((tmp_path / "receipts.jsonl").read_text().splitlines()[0].encode())


def test_records_never_hold_a_value_or_its_hash(make_session, tmp_path):
    s, _ = with_log(make_session, tmp_path, approve=lambda h, d, k: Approval(True, by="mia"))
    s.resolve_args({"text": "{{OTP_1}}"}, ACME)
    with pytest.raises(HandleRefused):
        s.resolve_args({"text": "{{OTP_1}}"}, Sink("type", "https://evil.example"))
    real = b"482913"
    forbidden = {real.decode(), digest(real), hashlib.sha256(real).hexdigest(),
                 base64.b64encode(hashlib.sha256(real).digest()).decode(),
                 base64.urlsafe_b64encode(real).decode().rstrip("="), real.hex()}
    for line in (tmp_path / "receipts.jsonl").read_text().splitlines():
        body = base64.urlsafe_b64decode(line.split(".")[1] + "==").decode()
        for needle in forbidden:
            assert needle not in body, needle
    assert verify_log(tmp_path, WRITER.public_key, s.vault)["problems"] == []


def test_call_is_the_digest_of_the_arguments_with_handles_unfilled(make_session, tmp_path):
    s, _ = with_log(make_session, tmp_path)
    args = {"text": "{{OTP_1}}", "n": 2.5, "deep": [1, {"b": None, "a": True}], "name": "é"}
    s.resolve_args(args, ACME)
    assert records(tmp_path)[0]["call"] == digest(canonical_args(args))
    assert canonical_args({"x": [1.0, 1e21, 0.1, -0.0, 100]}) == b'{"x":[1,1e+21,0.1,0,100]}'


def test_a_session_without_a_release_log_writes_nothing(make_session, tmp_path):
    s = make_session("browse_and_fill")
    s.mask(OTP_MAIL, Source(sender="no-reply@acme.com"))
    assert s.resolve_args({"text": "{{OTP_1}}"}, ACME).args == {"text": "482913"}
    assert s.release_log is None


def test_release_and_egress_records_share_one_chain(make_session, tmp_path):
    log = EgressLog(tmp_path, WRITER)
    s = make_session("browse_and_fill", release_log=log)
    m = s.mask(OTP_MAIL, Source(sender="no-reply@acme.com"))
    payload = json.dumps({"messages": [{"role": "user", "content": m.text}]}).encode()
    s.record_egress(log, payload, "api.example.com")
    s.resolve_args({"text": "{{OTP_1}}"}, ACME)
    s.record_egress(log, payload, "api.example.com")
    report = verify_log(tmp_path, WRITER.public_key, s.vault)
    assert (report["receipts"], report["releases"], report["rechecked"], report["problems"]) == (3, 1, 2, [])
    assert [r["type"] for r in records(tmp_path)] == ["egress", "release", "egress"]
    reopened = EgressLog(tmp_path, WRITER)
    assert (reopened.seq, reopened.prev) == (3, log.prev)


# verify_log on release records


def forge(tmp_path, **over):
    log = EgressLog(tmp_path, WRITER, store_payloads=False)
    fields = dict(session="s1", now=NOW, handle="{{OTP_1}}", data="OTP", source="acme.com",
                  sink={"tool": "type", "site": "acme.com"}, call=digest(b"x"), decision="allow",
                  authority={"kind": "binding"})
    fields.update(over)
    log.record_release(**fields)


def test_verify_log_finds_a_real_value_hidden_in_a_record(make_session, tmp_path):
    s, _ = with_log(make_session, tmp_path / "ok")
    forge(tmp_path, reason=None, authority={"kind": "person", "by": "code 482913"})
    report = verify_log(tmp_path, WRITER.public_key, s.vault)
    assert any("known value" in p and "record" in p for p in report["problems"]) and report["leaks"] == 1
    assert "482913" not in " ".join(report["problems"])


@pytest.mark.parametrize("over,field", [
    ({"handle": "OTP_1"}, "handle"),
    ({"data": "otp"}, "data"),
    ({"call": "sha-256:short"}, "call"),
    ({"uses_left": -1}, "uses_left"),
    ({"sink": {"tool": "type"}}, "sink"),
])
def test_verify_log_flags_a_malformed_release(tmp_path, over, field):
    if field == "sink":  # record_release builds the sink itself, so write the line by hand for this one
        from open_pseudonym.egress import release_body
        body = release_body(dict(session="s1", now=NOW, handle="{{OTP_1}}", data="OTP", source=None,
                                 sink={"tool": "type", "site": None}, call=digest(b"x"), decision="allow",
                                 authority={"kind": "binding"}), 1, None)
        body["sink"] = {"tool": "type"}
        (tmp_path / "receipts.jsonl").write_text(WRITER.sign(body, "opn-release+jws") + "\n")
    else:
        forge(tmp_path, **over)
    problems = verify_log(tmp_path, WRITER.public_key)["problems"]
    assert any(f"release 1: {field} is not valid" in p for p in problems), problems


def test_the_writer_refuses_to_sign_an_unlisted_code_or_kind(tmp_path):
    with pytest.raises(ValueError):
        forge(tmp_path, decision="deny", code="not_recorded", reason="x")
    with pytest.raises(ValueError):
        forge(tmp_path, decision="deny", code="made_up", reason="x")
    with pytest.raises(ValueError):
        forge(tmp_path, authority={"kind": "model"})


def test_a_tampered_release_line_breaks_the_chain(make_session, tmp_path):
    s, _ = with_log(make_session, tmp_path)
    for site in ("https://evil.example", "https://acme.com"):
        try:
            s.resolve_args({"text": "{{OTP_1}}"}, Sink("type", site))
        except HandleRefused:
            pass
    lines = (tmp_path / "receipts.jsonl").read_text().splitlines()
    (tmp_path / "receipts.jsonl").write_text(lines[1] + "\n")  # drop the first record
    problems = verify_log(tmp_path, WRITER.public_key)["problems"]
    assert any("sequence number" in p or "chain broken" in p for p in problems)


# Checkpoints


def six_records(tmp_path):
    log = EgressLog(tmp_path, WRITER, store_payloads=False)
    for n in range(6):
        log.record_release(session="s1", now=NOW + n, handle="{{OTP_1}}", data="OTP", source="acme.com",
                           sink={"tool": "type", "site": "acme.com"}, call=digest(bytes([n])), decision="allow",
                           authority={"kind": "binding"})
    return log


def cut_to(tmp_path, n):
    path = tmp_path / "receipts.jsonl"
    path.write_text("".join(ln + "\n" for ln in path.read_text().splitlines()[:n]))


def anchor_at(log_lines, seq, signer=ANCHOR, session="s1"):
    return make_checkpoint(signer, session=session, seq=seq, head=digest(log_lines[seq - 1].encode()), now=NOW)


def test_a_log_cut_short_is_a_prefix_without_an_anchor(tmp_path):
    six_records(tmp_path)
    cut_to(tmp_path, 4)
    report = verify_log(tmp_path, WRITER.public_key)
    assert (report["problems"], report["proven_to"], report["status"], report["reason"]) == (
        [], None, "prefix", "no_anchor")


def test_an_anchor_past_the_end_shows_the_cut(tmp_path):
    log = six_records(tmp_path)
    all_lines = (tmp_path / "receipts.jsonl").read_text().splitlines()
    cp = log.checkpoint(ANCHOR, session="s1", now=NOW)
    cut_to(tmp_path, 4)
    report = verify_log(tmp_path, WRITER.public_key, anchors=[cp], anchor_key=ANCHOR.public_key)
    assert report["problems"] == ["anchor at seq 6: the log was cut off after seq 4"]
    assert (report["proven_to"], report["status"]) == (None, "prefix")
    assert cp == anchor_at(all_lines, 6)


def test_an_anchor_inside_the_log_proves_that_far(tmp_path):
    six_records(tmp_path)
    lines = (tmp_path / "receipts.jsonl").read_text().splitlines()
    cut_to(tmp_path, 4)
    report = verify_log(tmp_path, WRITER.public_key, anchors=[anchor_at(lines, 3)], anchor_key=ANCHOR.public_key)
    assert (report["problems"], report["proven_to"], report["status"], report["reason"]) == (
        [], 3, "prefix", "unanchored_tail")


def test_an_anchor_at_the_last_record_is_complete(tmp_path):
    six_records(tmp_path)
    lines = (tmp_path / "receipts.jsonl").read_text().splitlines()
    report = verify_log(tmp_path, WRITER.public_key, anchors=[anchor_at(lines, 3), anchor_at(lines, 6)],
                        anchor_key=ANCHOR.public_key)
    assert (report["problems"], report["proven_to"], report["status"], report["reason"]) == ([], 6, "complete", None)


def test_an_anchor_whose_head_does_not_match_is_a_problem(tmp_path):
    six_records(tmp_path)
    lines = (tmp_path / "receipts.jsonl").read_text().splitlines()
    lines[2], lines[3] = lines[3], lines[2]  # records swapped, so record 3 is no longer the one anchored
    wrong = make_checkpoint(ANCHOR, session="s1", seq=3, head=digest(b"another log"), now=NOW)
    report = verify_log(tmp_path, WRITER.public_key, anchors=[wrong], anchor_key=ANCHOR.public_key)
    assert any("anchor at seq 3: head does not match" in p for p in report["problems"])
    assert report["proven_to"] is None and report["status"] == "prefix"


def test_an_anchor_signed_by_the_writers_own_key_counts_for_nothing(tmp_path):
    six_records(tmp_path)
    lines = (tmp_path / "receipts.jsonl").read_text().splitlines()
    own = anchor_at(lines, 6, signer=WRITER)
    report = verify_log(tmp_path, WRITER.public_key, anchors=[own], anchor_key=WRITER.public_key)
    assert any("the key that signs the log" in p for p in report["problems"])
    assert (report["proven_to"], report["status"]) == (None, "prefix")


def test_a_wrong_key_wrong_session_or_missing_key_is_a_problem(tmp_path):
    six_records(tmp_path)
    lines = (tmp_path / "receipts.jsonl").read_text().splitlines()
    other = Signer.from_seed(bytes([9] * 32))
    r = verify_log(tmp_path, WRITER.public_key, anchors=[anchor_at(lines, 6, signer=other)],
                   anchor_key=ANCHOR.public_key)
    assert r["problems"] == ["anchor 1: unknown key"] and r["status"] == "prefix"
    r = verify_log(tmp_path, WRITER.public_key, anchors=[anchor_at(lines, 6, session="s2")],
                   anchor_key=ANCHOR.public_key)
    assert r["problems"] == ["anchor 1: belongs to another session"]
    r = verify_log(tmp_path, WRITER.public_key, anchors=[anchor_at(lines, 6)])
    assert r["problems"] == ["anchors were given without an anchor_key to check them with"]


def test_a_log_cannot_checkpoint_itself(tmp_path):
    log = six_records(tmp_path)
    with pytest.raises(ValueError):
        log.checkpoint(WRITER, session="s1", now=NOW)
    with pytest.raises(ValueError):
        EgressLog(tmp_path / "empty", WRITER).checkpoint(ANCHOR, session="s1", now=NOW)


def test_expect_count_and_expect_last_still_work(tmp_path):
    log = six_records(tmp_path)
    last = log.prev
    cut_to(tmp_path, 4)
    problems = verify_log(tmp_path, WRITER.public_key, expect_count=6, expect_last=last)["problems"]
    assert len(problems) == 2 and "expected 6 receipt(s), found 4" in problems[0]


# Sensitive references stay opaque

SREF_BARE = "sref:contact:4242424242424242abcd"  # digits that look like a card, in a valid reference
SREF_BRACKET = "⟦sref:account:01JCK7KF9X4Y3M4N6Q6YB2D8P0⟧"


def test_the_two_forms_are_found_and_lookalikes_are_not():
    text = f"a {SREF_BARE} b {SREF_BRACKET}"
    found = [text[b:e] for b, e in sref_regions(text)]
    assert found == [SREF_BARE, SREF_BRACKET]
    for no in ("sref:email:short", "xsref:email:" + "A" * 26, "sref:" + "k" * 33 + ":" + "A" * 26,
               "sref:email:" + "A" * 129 + "!"):
        assert sref_regions(no) == [], no


def test_a_reference_is_never_masked(make_session):
    s = make_session("strict")
    m = s.mask(f"card {SREF_BARE} and {SREF_BRACKET} and Dana Reyes")
    assert SREF_BARE in m.text and SREF_BRACKET in m.text and "Dana" not in m.text
    assert all(r.type != "CARD" for r in m.replacements)


def test_a_reference_is_never_a_stand_in_or_restored(make_session):
    s = make_session("strict")
    s.mask(f"{SREF_BARE} call (617) 555-0142")
    fake = next(e.stand_in for e in s.vault.entries if e.type == "PHONE")
    digits = "".join(c for c in fake if c.isdigit())
    assert s.restore(f"{SREF_BARE} {SREF_BRACKET}") == f"{SREF_BARE} {SREF_BRACKET}"
    inside = "sref:contact:AB" + digits + "CDEFGHJK"
    assert sref_regions(inside) and s.restore(inside) == inside  # a fake's digits inside a reference stay
    assert s.restore(f"call {digits}") == "call 6175550142"  # the same digits outside one are restored
    assert s.unknown_stand_ins(f"{SREF_BARE} {SREF_BRACKET}") == []


def test_a_reference_split_across_stream_chunks_is_never_restored(make_session):
    s = make_session("strict")
    s.mask("call (617) 555-0142")
    fake = next(e.stand_in for e in s.vault.entries if e.type == "PHONE")
    digits = "".join(c for c in fake if c.isdigit())
    text = "ok " + "x" * 60 + " sref:contact:AB" + digits + "CDEFGHJK done " + "y" * 200
    for size in (1, 3, 7, 50):
        st = s.stream()
        out = "".join(st.feed(text[i:i + size]) for i in range(0, len(text), size)) + st.flush()
        assert out == text, size


def test_a_reference_is_never_filled_and_a_handle_never_resolves_to_one(make_session):
    s = make_session("browse_and_fill")
    s.mask(OTP_MAIL, Source(sender="no-reply@acme.com"))
    args = {"ref": SREF_BARE, "other": SREF_BRACKET}
    r = s.resolve_args(args, ACME)
    assert r.args == args and r.report == []  # not restored, not flagged as something the model wrote
    for fake_handle in ("{{SREF_1}}", "{{sref_1}}"):
        if fake_handle == "{{sref_1}}":
            assert s.resolve_args({"t": fake_handle}, ACME).args == {"t": fake_handle}  # not a handle at all
        else:
            with pytest.raises(HandleRefused) as e:
                s.resolve_args({"t": fake_handle}, ACME)
            assert e.value.code == "unknown_handle"


def test_a_reference_is_never_an_egress_leak(make_session):
    s = make_session("strict")
    s.mask("Hi Dana,\nok")
    payload = json.dumps({"messages": [{"role": "user", "content": f"use {SREF_BARE} and {SREF_BRACKET}"}]})
    assert s.check_egress(payload) == []
    assert s.check_egress("use 4242 4242 4242 4242 and " + SREF_BARE)  # a real card number beside one still is
