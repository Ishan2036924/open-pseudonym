"""The egress check and receipts, including planted defects that must be caught."""

import json

import pytest

from open_pseudonym import EgressLeak, EgressLog, Signer, verify_log
from open_pseudonym.jws import SignatureError, verify

TEXT = "From: Dana Reyes <dana.reyes@gmail.com>\nHi Sam,\nCall (617) 555-0142.\nDana"


def test_masked_payload_is_clean_and_real_one_is_not(make_session):
    s = make_session()
    m = s.mask(TEXT)
    assert s.check_egress(m.text) == []
    assert {lk.type for lk in s.check_egress(TEXT)} >= {"PERSON", "EMAIL", "PHONE"}


@pytest.mark.parametrize("planted", ["Dana", "DANA.REYES@GMAIL.COM", "617 555 0142", "Reyes"])
def test_planted_real_value_is_caught(make_session, planted):
    s = make_session()
    m = s.mask(TEXT)
    assert s.check_egress(m.text + " " + planted), planted


def test_json_escapes_cannot_hide_a_name(make_session):
    s = make_session()
    s.mask("Hi José Núñez,\nok")
    body = json.dumps({"messages": [{"role": "user", "content": "for José Núñez"}]})  # ensure_ascii escapes it
    assert "\\u00e9" in body
    assert s.check_egress(body)


def test_receipts_chain_and_verify(make_session, tmp_path):
    s = make_session()
    signer = Signer.from_seed(bytes(range(32)))
    log = EgressLog(tmp_path, signer)
    for text in [TEXT, "and Dana again"]:
        payload = json.dumps({"messages": [{"role": "user", "content": s.mask(text).text}]}).encode()
        s.record_egress(log, payload, "api.example.com")
    report = verify_log(tmp_path, signer.public_key, s.vault)
    assert {k: report[k] for k in ("receipts", "rechecked", "leaks", "problems")} == {
        "receipts": 2, "rechecked": 2, "leaks": 0, "problems": []}
    body = verify((tmp_path / "receipts.jsonl").read_text().splitlines()[0], signer.public_key, "opn-egress+jws")
    # "Dana Reyes", "Sam" and the sign-off "Dana" are three entries; the email and phone one each
    assert body["stand_ins"] == {"EMAIL": 1, "PERSON": 3, "PHONE": 1}
    assert body["check"]["found"] == 0 and body["prev"] is None


def test_leak_is_refused_and_nothing_is_written(make_session, tmp_path):
    s = make_session()
    s.mask(TEXT)
    log = EgressLog(tmp_path, Signer.from_seed(bytes(32)))
    with pytest.raises(EgressLeak) as e:
        s.record_egress(log, TEXT.encode(), "api.example.com")
    assert "Dana" not in str(e.value) and not (tmp_path / "receipts.jsonl").exists()


def test_tampering_is_found(make_session, tmp_path):
    s = make_session()
    signer = Signer.from_seed(bytes(32))
    log = EgressLog(tmp_path, signer)
    for text in ["Hi Dana,\nx", "Hi Sam,\ny", "Hi Omar,\nz"]:
        s.record_egress(log, s.mask(text).text.encode(), "api.example.com")
    (tmp_path / "payloads" / "000002.bin").write_bytes(b"Hi Dana,\nleaked after the fact")
    lines = (tmp_path / "receipts.jsonl").read_text().splitlines()
    (tmp_path / "receipts.jsonl").write_text("\n".join([lines[0], lines[2], lines[1]]) + "\n")
    problems = verify_log(tmp_path, signer.public_key, s.vault)["problems"]
    assert any("chain broken" in p for p in problems)
    assert any("does not match its digest" in p for p in problems)
    other = Signer.from_seed(b"\x07" * 32)
    assert all("unknown key" in p for p in verify_log(tmp_path, other.public_key)["problems"])


def test_signatures_are_deterministic_and_checked():
    signer = Signer.from_seed(bytes(32))
    token = signer.sign({"a": 1}, "opn-egress+jws")
    assert token == signer.sign({"a": 1}, "opn-egress+jws")
    bad = token[:-2] + ("A" if token[-2] != "A" else "B") + token[-1]
    with pytest.raises(SignatureError):
        verify(bad, signer.public_key, "opn-egress+jws")


@pytest.mark.parametrize("payload", ['4242424242424242', '"4242 4242 4242 4242"', '[4242424242424242]'])
def test_bare_json_values_cannot_hide_a_number(make_session, payload):
    s = make_session("training_data")
    s.mask("card 4242 4242 4242 4242")
    assert {lk.type for lk in s.check_egress(payload)} == {"CARD"}


def test_stopword_name_parts_do_not_raise_false_alarms(make_session):
    s = make_session("strict", known={"PERSON": ["May Chen"]})
    s.mask("lunch with May Chen")
    assert s.check_egress("see you in May") == []


def test_verify_reports_missing_payloads_cut_tails_and_damaged_lines(make_session, tmp_path):
    """Critic finding: a deleted payload or a cut tail used to pass, and a bad line crashed the check."""
    s = make_session()
    signer = Signer.from_seed(bytes(32))
    log = EgressLog(tmp_path, signer)
    for text in ["Hi Dana,\nx", "Hi Sam,\ny", "Hi Omar,\nz"]:
        s.record_egress(log, s.mask(text).text.encode(), "api.example.com")
    full = verify_log(tmp_path, signer.public_key, s.vault)
    assert full["problems"] == [] and full["receipts"] == 3
    (tmp_path / "payloads" / "000002.bin").unlink()
    assert "receipt 2: its stored payload is missing" in verify_log(tmp_path, signer.public_key)["problems"]
    lines = (tmp_path / "receipts.jsonl").read_text().splitlines()
    (tmp_path / "receipts.jsonl").write_text(lines[0] + "\n")
    assert verify_log(tmp_path, signer.public_key, expect_count=3)["problems"][-1].startswith("expected 3")
    assert verify_log(tmp_path, signer.public_key, expect_last=full["last"])["problems"][-1].startswith("the last")
    from open_pseudonym.jcs import b64url

    forged = b64url(b'{"alg":"EdDSA","kid":"x","typ":"\\ud800"}') + "." + b64url(b"{}") + ".AAAA"
    (tmp_path / "receipts.jsonl").write_text(lines[0] + "\n" + forged + "\n")
    report = verify_log(tmp_path, signer.public_key)
    assert any("receipt 2" in p for p in report["problems"])


def test_verify_catches_a_missing_log_orphan_payloads_and_another_sessions_log(make_session, tmp_path):
    s = make_session()
    signer = Signer.from_seed(bytes(32))
    log = EgressLog(tmp_path, signer)
    for text in ["Hi Dana,\nx", "Hi Sam,\ny"]:
        s.record_egress(log, s.mask(text).text.encode(), "api.example.com")
    assert verify_log(tmp_path, signer.public_key, expect_session=s.id)["problems"] == []
    assert any("another session" in p for p in verify_log(tmp_path, signer.public_key, expect_session="x")["problems"])
    (tmp_path / "receipts.jsonl").write_text("")
    assert any("have no receipt" in p for p in verify_log(tmp_path, signer.public_key)["problems"])
    (tmp_path / "receipts.jsonl").unlink()
    assert "there is no receipts.jsonl in this folder" in verify_log(tmp_path, signer.public_key)["problems"]


def test_deeply_nested_payloads_do_not_crash_the_check(make_session):
    s = make_session()
    s.mask("Hi Dana,\nok")
    assert s.check_egress("[" * 3000 + "]" * 3000) == []
    assert s.check_egress("[" * 3000 + '"Dana"' + "]" * 3000)


def test_verify_notices_an_empty_log_and_a_removed_payload_folder(make_session, tmp_path):
    import shutil

    s = make_session()
    signer = Signer.from_seed(bytes(32))
    s.record_egress(EgressLog(tmp_path, signer), s.mask("Hi Dana,\nx").text.encode(), "api.example.com")
    shutil.rmtree(tmp_path / "payloads")
    assert any("no stored payloads" in p for p in verify_log(tmp_path, signer.public_key, s.vault)["problems"])
    (tmp_path / "receipts.jsonl").write_text("")
    assert "the log holds no receipts" in verify_log(tmp_path, signer.public_key)["problems"]


def test_odd_json_shapes_do_not_crash(make_session):
    s = make_session()
    msgs, _ = s.mask_messages([{"role": "user", "content": [{"type": ["x"], "signature": "call (617) 555-0142"}]}])
    assert "555-0142" not in json.dumps(msgs)
    assert s.check_egress('{"type": {"a": 1}, "signature": "x"}') == []
