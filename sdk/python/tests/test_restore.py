"""Restoring: the person gets back exactly what they wrote, streamed or not."""

import random

import pytest

from open_pseudonym import Source

TEXTS = [
    "From: Dana Reyes <dana.reyes@gmail.com>\nHi Sam,\nCall (617) 555-0142 on March 12, 2026.\nDana",
    "Invoice for Northwind Traders Inc. to 221 Baker Street, Apt 4; card 4242 4242 4242 4242.",
    "I will meet Priya Raman and Omar Haddad at https://meet.acme.com/r/9921xq on 2026-04-02.",
    "Your verification code is 482913. Password: Tr0ub4dor&3 for priya@acme.co.uk",
]


@pytest.mark.parametrize("text", TEXTS)
@pytest.mark.parametrize("profile", ["draft_reply", "strict", "training_data", "browse_and_fill"])
def test_round_trip(make_session, text, profile):
    s = make_session(profile)
    masked = s.mask(text, Source(sender="no-reply@acme.com"))
    if profile == "training_data":  # secrets are dropped there, so only the rest can come back
        return
    assert s.restore(masked.text, reveal_handles=True) == text


@pytest.mark.parametrize("seed", range(12))
def test_stream_matches_whole_restore(make_session, seed):
    s = make_session("strict")
    masked = s.mask(TEXTS[0] + "\n" + TEXTS[2]).text
    rng = random.Random(seed)
    st = s.stream()
    out, i = [], 0
    while i < len(masked):
        n = rng.randint(1, 9)
        out.append(st.feed(masked[i:i + n]))
        i += n
    out.append(st.flush())
    assert "".join(out) == s.restore(masked)


def test_model_reformatting_still_restores(make_session):
    s = make_session("draft_reply")
    m = s.mask("Call (617) 555-0142 on 2026-03-12, Dana Reyes")
    phone = m.text.split("Call ")[1].split(" on")[0]
    digits = "".join(c for c in phone if c.isdigit())
    shifted = m.text.split(" on ")[1].split(",")[0]
    y, mo, d = shifted.split("-")
    months = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October",
              "November", "December"]
    reply = f"I'll ring {digits[:3]}.{digits[3:6]}.{digits[6:]} on {months[int(mo) - 1]} {int(d)}."
    assert s.restore(reply) == "I'll ring 617.555.0142 on March 12."


def test_word_edges(make_session):
    s = make_session()
    m = s.mask("Hi Dana,\nok")
    fake = m.text.split("Hi ")[1].split(",")[0]
    assert s.restore(f"{fake}'s plan") == "Dana's plan"
    assert s.restore(f"{fake}xyz stays") == f"{fake}xyz stays"


def test_handles_show_a_label_by_default(make_session):
    s = make_session()
    m = s.mask("Your verification code is 482913.", Source(sender="no-reply@acme.com"))
    assert "{{OTP_1}}" in m.text
    shown = s.restore("Use {{OTP_1}} now")
    assert "482913" not in shown and "one-time code from acme.com" in shown
    assert s.restore("Use {{OTP_1}} now", reveal_handles=True) == "Use 482913 now"


def test_unknown_stand_ins_are_reported_not_guessed(make_session):
    s = make_session("strict")
    s.mask("Hi Dana,\nok")
    assert s.unknown_stand_ins("ask [PERSON_7] about {{OTP_3}}") == ["[PERSON_7]", "{{OTP_3}}"]
    assert s.restore("ask [PERSON_7]") == "ask [PERSON_7]"
