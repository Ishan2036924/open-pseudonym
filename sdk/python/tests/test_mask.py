"""Masking: stand-ins are consistent, keep their type and shape, and come from reserved ranges."""

import datetime as dt
import json
import re

import pytest

from open_pseudonym import RefusedData, Session, Vault
from open_pseudonym.checks import aba_ok, iban_ok, luhn_ok
from open_pseudonym._data import pools
from open_pseudonym.policy import Policy, load_profile

def policy_with(profile, rules):
    """A profile with some rules swapped. Built as a new document on purpose: `with_rules` only tightens."""
    doc = load_profile(profile).to_dict()
    doc["rules"].update(rules)
    return Policy.from_dict(doc)


EMAIL = """From: Dana Reyes <dana.reyes@gmail.com>
Hi Sam,

Can we move Thursday's call to March 12, 2026? Call me at (617) 555-0142.
Dana"""


def test_same_person_same_fake_everywhere(make_session):
    s = make_session()
    m = s.mask(EMAIL)
    fake_full = re.search(r"From: (.+?) <", m.text)[1]
    first, last = fake_full.split()
    assert "Dana" not in m.text and "Reyes" not in m.text
    assert m.text.rstrip().endswith(first)  # the sign-off "Dana" became the same fake first name
    local = re.search(r"<(.+?)@", m.text)[1]
    assert local == f"{first.lower()}.{last.lower()}"  # dana.reyes@ followed the name
    again = s.mask("Dana Reyes and DANA REYES said hi")
    assert again.text == f"{fake_full} and {fake_full.upper()} said hi"


def test_fakes_use_reserved_ranges(make_session):
    s = make_session("training_data")
    m = s.mask(
        "dana@acme.com, (617) 555-0142, 10.0.0.7, card 4111 1111 1111 1111, SSN 123-45-6789, "
        "routing 021000021, IBAN DE89 3704 0044 0532 0130 00"
    )
    t = m.text
    assert re.search(r"@[a-z]+\.example", t)
    assert re.search(r"\(\d{3}\) 555-01\d\d", t)
    assert re.search(r"(192\.0\.2|198\.51\.100|203\.0\.113)\.\d+", t)
    s2 = Session(policy_with("training_data", {"CARD": {"action": "fake"}, "SSN": {"action": "fake"},
                                                "ROUTING": {"action": "fake"}, "IBAN": {"action": "fake"}}),
                 Vault(seed=bytes(32)))
    t2 = s2.mask("card 4111 1111 1111 1111, SSN 123-45-6789, routing 021000021, IBAN DE89 3704 0044 0532 0130 00").text
    card = re.search(r"card ([\d ]+),", t2)[1].replace(" ", "")
    assert card in pools()["test_cards"] and luhn_ok(card)
    assert re.search(r"SSN 987-65-432\d", t2)
    routing = re.search(r"routing (\d{9})", t2)[1]
    assert routing.startswith("0000") and sum(
        w * int(d) for w, d in zip([3, 7, 1] * 3, routing)) % 10 == 0
    assert iban_ok(re.search(r"IBAN ([A-Z0-9 ]+)$", t2)[1])


def test_dates_shift_together_and_keep_the_weekday(make_session):
    s = make_session("draft_reply")
    m = s.mask("Thu 2026-03-12, then March 19, 2026, then 3/26/2026")
    days = re.findall(r"\d{4}-\d{2}-\d{2}|[A-Z][a-z]+ \d+, \d{4}|\d+/\d+/\d{4}", m.text)
    assert len(days) == 3
    first = dt.date.fromisoformat(days[0])
    assert first.weekday() == dt.date(2026, 3, 12).weekday()
    offset = s.vault.date_offset
    assert offset % 7 == 0 and offset != 0 and abs(offset) <= 26 * 7
    assert days[1] == (dt.date(2026, 3, 19) + dt.timedelta(days=offset)).strftime("%B %-d, %Y")


def test_money_scales_consistently(make_session):
    s = make_session("training_data")
    s.policy = s.policy.with_rules({"MONEY": {"action": "fake"}})
    m = s.mask("Rent $1,200.00 plus utilities $300.00 is $1,500.00")
    amounts = [int(a.replace(",", "").replace(".", "")) for a in re.findall(r"\$([\d,]+\.\d\d)", m.text)]
    assert amounts[0] + amounts[1] == amounts[2]
    assert amounts[0] != 120000


def test_masking_twice_changes_nothing_when_the_app_says_so(make_session):
    s = make_session(masked_input=True)
    once = s.mask(EMAIL).text
    assert s.mask(once).text == once


def test_a_real_name_equal_to_an_earlier_fake_is_still_masked(make_session):
    """Critic finding: a real 'Ellis' after Dana became 'Ellis' used to reach the model as is."""
    s = make_session()
    fake = s.mask("Hi Dana,\nok").text.split("Hi ")[1].split(",")[0]
    real_text = f"Hi {fake},\nthis is a different person who really has that name"
    m = s.mask(real_text)
    assert not m.text.startswith(f"Hi {fake},")  # masked like any other name
    assert s.restore(m.text) == real_text


def test_same_seed_same_output(make_session):
    assert make_session().mask(EMAIL).text == make_session().mask(EMAIL).text
    assert make_session(seed=b"\x01" * 32).mask(EMAIL).text != make_session().mask(EMAIL).text


def test_refuse_stops_the_request(make_session):
    s = make_session()
    s.policy = s.policy.with_rules({"SSN": {"action": "refuse"}})
    with pytest.raises(RefusedData):
        s.mask("SSN 123-45-6789")


def test_tags_tokens_drop_generalize(make_session):
    p = Policy.from_dict({
        "opn": "0.1", "type": "policy", "id": "mix",
        "rules": {"PERSON": {"action": "tag"}, "EMAIL": {"action": "token"}, "PHONE": {"action": "drop"},
                  "DATE": {"action": "generalize"}, "MONEY": {"action": "generalize"}},
        "default": {"action": "keep"},
    })
    s = Session(p, Vault(seed=bytes(32)))
    m = s.mask("Hi Dana,\nmail dana@acme.com or (617) 555-0142 by 2026-03-12 about $1,234.56")
    assert m.text.startswith("Hi [PERSON_1],")
    assert re.search(r"email_[0-9a-f]{8}", m.text)
    assert "[PHONE removed]" in m.text and "March 2026" in m.text and "about $1,200" in m.text


def test_tokens_are_stable_across_vaults_with_a_pinned_key():
    a, b = Vault(seed=b"a" * 32), Vault(seed=b"b" * 32)
    a.token_key = b.token_key = b"k" * 32
    sa, sb = Session("logs", a), Session("logs", b)
    assert sa.mask("user dana@acme.com failed").text == sb.mask("user dana@acme.com failed").text


def test_fpe_keeps_shape_and_reverses_with_the_key_alone():
    p = policy_with("training_data", {"CARD": {"action": "fpe"}, "ROUTING": {"action": "fpe"}})
    s = Session(p, Vault(seed=bytes(32)))
    m = s.mask("card 4111 1111 1111 1111 routing 021000021")
    card = re.search(r"card ([\d ]+) routing", m.text)[1]
    routing = re.search(r"routing (\d+)", m.text)[1]
    assert card.startswith("4") and card.endswith("1111") and luhn_ok(card.replace(" ", ""))
    assert card != "4111 1111 1111 1111" and aba_ok(routing)
    assert s.fpe_decrypt("CARD", card) == "4111 1111 1111 1111"
    assert s.fpe_decrypt("ROUTING", routing) == "021000021"


def test_keep_gender(make_session):
    names = pools()["first_names"]
    m = make_session().mask("I will meet Maria Lopez and James Okoro")
    fakes = re.findall(r"meet (\w+) \w+ and (\w+)", m.text)[0]
    assert fakes[0] in names["f"] and fakes[1] in names["m"]


def test_unknown_type_uses_the_default(make_session):
    s = make_session("strict", extra_patterns=[{"type": "EMPLOYEE_ID", "pattern": "E-[0-9]{6}", "priority": 60}])
    assert s.mask("badge E-123456 lost").text == "badge [EMPLOYEE_ID_1] lost"


def test_a_fake_never_equals_the_real_value():
    """Across many seeds and every fakeable type, the stand-in must differ from what it replaces."""
    text = ("Hi Dana Reyes,\nmail dana@acme.com, ring +44 7700 900123 or (617) 555-0142, see 10.0.0.7 and "
            "https://acme.com/x?id=42, ship to 221 Baker Street, card 4242 4242 4242 4242, SSN 123-45-6789, "
            "IBAN GB82 WEST 1234 5698 7654 32, routing 021000021, password: hunter2!x, code 482913")
    p = policy_with("training_data", {t: {"action": "fake"} for t in
                                      ["CARD", "SSN", "IBAN", "ROUTING", "PASSWORD", "OTP"]})
    for i in range(200):
        s = Session(p, Vault(seed=i.to_bytes(2, "big") * 16))
        m = s.mask(text)
        for r in m.replacements:
            real = s.vault.by_id(r.entry_id).surfaces[r.stand_in]
            assert r.stand_in.lower() != real.lower(), (i, r.type, real)


def test_name_slugs_in_links_are_hidden(make_session):
    """Critic finding: /in/danareyes kept the name."""
    s = make_session("strict")
    m = s.mask("I will meet Dana Reyes, see https://social.example.com/in/danareyes")
    assert "danareyes" not in m.text


def test_lowercase_names_are_caught_once_known(make_session):
    """Critic finding: 'dana reyes' in lower case passed both masking and the egress check."""
    s = make_session("strict")
    s.mask("I will meet Dana Reyes")
    assert "dana reyes" not in s.mask("dana reyes called back").text
    assert s.check_egress("then dana reyes said hi")


def test_known_names_match_across_any_whitespace(make_session):
    """Critic finding: 'dana  reyes' and 'dana\\nreyes' passed masking and the egress check."""
    s = make_session("strict")
    s.mask("I will meet Dana Reyes")
    for text in ["dana  reyes called", "dana\nreyes called", "dana reyes called"]:
        assert "reyes" not in s.mask(text).text.lower(), repr(text)
        assert s.check_egress(text), repr(text)


def test_keys_of_tool_results_are_masked(make_session):
    s = make_session("strict")
    masked, _ = s.mask_json({"dana.reyes@gmail.com": {"name": "Dana Reyes"}})
    assert "dana" not in json.dumps(masked).lower()


def test_long_input_stays_fast(make_session):
    import time

    s = make_session("strict")
    text = "a." * 50_000 + " mail dana@acme.com"
    t0 = time.perf_counter()
    s.mask(text)
    assert time.perf_counter() - t0 < 3.0  # was about 12 s for 100 KB before the email pattern was bounded


def test_a_known_contacts_name_parts_are_caught_alone(make_session):
    s = make_session("strict", known={"PERSON": ["Dana Reyes"]})
    out = s.mask("Dana called, and later Reyes, Dana wrote back").text
    assert "Dana" not in out and "Reyes" not in out
