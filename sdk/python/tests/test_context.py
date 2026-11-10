"""The 0.2 context fixes. Each test is a case that went wrong in 0.1.1, kept here so it stays fixed."""

import datetime as dt

import pytest

from open_pseudonym import Session, Vault, load_level

NOW = 1793836800  # 2026-11-05


def strict(profile="strict"):
    return Session(profile, Vault(seed=b"q" * 32), clock=lambda: NOW)


@pytest.mark.parametrize("text, reals", [
    ("I met Priya yesterday and she said the deal is off.", ["Priya"]),
    ("this is Sam Patel from Acme Corp", ["Sam", "Patel", "Acme"]),
    ("Daniel Smith signed. D. Smith initialed page 2.", ["Daniel", "Smith"]),
    ("Wei Zhang and Oluwaseun Adeyemi joined the call with José García.",
     ["Wei", "Zhang", "Oluwaseun", "Adeyemi", "José", "García"]),
    ("Notes from Nguyễn Văn An: budget approved.", ["Nguyễn"]),
    ("Hola María, ¿podemos vernos?", ["María"]),
    ("Priya van der Berg called.", ["Priya", "Berg"]),
])
def test_names_without_a_cue(text, reals):
    masked = strict().mask(text).text
    for real in reals:
        assert real not in masked, (real, masked)


def test_a_name_is_never_half_hidden():
    # 0.1.1 sent "Dana Yilmaz": the surname was known from "Ms. Reyes", the first name went out as is
    s = strict()
    masked = s.mask("Ms. Reyes called. Dana Reyes wants a refund. Met Zorblax Reyes too.").text
    assert "Dana" not in masked and "Zorblax" not in masked and "Reyes" not in masked
    assert s.restore(masked) == "Ms. Reyes called. Dana Reyes wants a refund. Met Zorblax Reyes too."


def test_particles_stay_lower_case():
    masked = strict().mask("Priya van der Berg called.").text
    assert " van der " in masked


def test_records_places_postcodes_handles():
    s = strict()
    text = ("Patient MRN 448812 at St. Mary's Hospital in Boise, Idaho. I live at 221B Baker Street, London NW1 6XE. "
            "Profile https://linkedin.com/in/dana-reyes or @dana_r; order #A12345 for CUST-00921.")
    masked = s.mask(text).text
    for real in ["448812", "Mary", "Boise", "Baker", "NW1 6XE", "dana-reyes", "@dana_r", "A12345", "CUST-00921"]:
        assert real not in masked, real
    assert "ZZ99 " in masked  # a postcode no real address uses
    assert s.restore(masked) == text


def test_standards_and_code_annotations_are_not_personal():
    s = strict()
    text = "See ISO-8601, CVE-2024-12345 and the @property decorator."
    assert s.mask(text).text == text


def test_a_company_and_its_bare_name_share_one_fake():
    s = strict()
    masked = s.mask("I work at Acme Corp; Acme pays well.").text
    fake = masked.split("work at ")[1].split(" Corp")[0]
    assert "Acme" not in masked and f"; {fake} pays well" in masked


def test_companies_named_after_people_are_companies():
    spans = strict().detect("Morgan Stanley hired Morgan Lee.")
    assert [(sp.type, sp.text) for sp in spans] == [("ORG", "Morgan Stanley"), ("PERSON", "Morgan Lee")]


def test_holidays_keep_their_date_and_are_not_leaks():
    s = strict()
    masked = s.mask("On Christmas Day, December 25, 2026, the office is closed. We meet March 12, 2026.").text
    assert "Christmas Day, December 25, 2026" in masked and "March 12, 2026" not in masked
    assert s.check_egress(masked) == []


def test_a_birth_date_keeps_the_age():
    s = strict()
    masked = s.mask("I was born March 3, 1990, so I am 36.").text
    assert "March 3, 1990" not in masked
    shifted = dt.datetime.strptime(masked.split("born ")[1].split(", so")[0], "%B %d, %Y").date()
    today = dt.date(2026, 11, 5)
    assert today.year - shifted.year - ((today.month, today.day) < (shifted.month, shifted.day)) == 36


def test_dates_move_by_at_most_eight_weeks():
    for seed in range(40):
        offset = Vault(seed=bytes([seed]) * 32).get_date_offset()
        assert offset % 7 == 0 and 7 <= abs(offset) <= 56


def test_summaries_keep_coarse_places_and_blur_precise_ones():
    s = strict("summarize")
    masked = s.mask("She moved from Boise, Idaho to Kenya; ZIP 02115. Later: Smalltown, MT.").text
    assert masked == "She moved from a city, Idaho to Kenya; ZIP 021xx. Later: a town in Montana."
    assert s.check_egress(masked) == []


def test_the_contacts_level_keeps_a_name_and_does_not_report_it():
    # the bug Atlas found in 0.1.1: faking the email registered the name, so the kept name looked like a leak
    s = Session(load_level(2), Vault(seed=b"z" * 32))
    masked = s.mask("email dana.reyes@acme.com and tell Dana hi").text
    assert "dana.reyes" not in masked and "Dana" in masked
    assert s.check_egress(masked) == []


def test_a_slice_of_a_long_fake_is_not_a_leak():
    s = strict()
    masked = s.mask("Notes from Nguyễn Văn An and Priya van der Berg.").text
    assert s.check_egress(masked) == []


def test_real_values_planted_after_masking_are_caught():
    s = strict()
    text = "Patient MRN 448812, Dana Reyes, Boise, Idaho, @dana_r, CUST-00921."
    masked = s.mask(text).text
    for real in ["448812", "Dana Reyes", "Boise", "@dana_r", "CUST-00921"]:
        assert s.check_egress(masked + " " + real), real


def test_policy_for_combines_the_task_and_the_level():
    from open_pseudonym import policy_for

    schedule = policy_for("schedule")
    assert schedule.rule_for("DATE").action == "keep"
    # level 2 hides contacts, which scheduling already fakes; names stay faked; dates stay real for the calendar
    combined = policy_for("schedule", 2)
    assert combined.rule_for("PERSON").action == "fake" and combined.rule_for("DATE").action == "keep"
    # a level can only add hiding: strict shifts dates, so the combination shifts them too
    assert policy_for("schedule", 3).rule_for("DATE").action == "shift"


@pytest.mark.parametrize("text", [
    "Please order 10000 units by Friday.",
    "Let's meet @3pm.",
    "The Data Center and the Customer Support Center moved.",
    "Use the Oxford comma and wear Wellington boots.",
])
def test_everyday_text_is_left_alone(text):
    assert strict().mask(text).text == text


def test_a_word_like_name_is_hidden_only_where_a_cue_finds_it():
    s = strict()
    text = "Hi Will,\nWill you join? Thanks, Will"
    masked = s.mask(text).text
    assert "Will you join?" in masked and masked.count("Will") == 1
    assert s.check_egress(masked) == [] and s.restore(masked) == text
