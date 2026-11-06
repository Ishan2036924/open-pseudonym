"""Detection: each type is found where it should be, and the usual look-alikes are not."""

import pytest

from open_pseudonym.detect import KnownDetector, Span, resolve
from open_pseudonym.session import Session


def found(text, session=None):
    s = session or Session("strict")
    return [(sp.type, sp.text) for sp in s.detect(text)]


@pytest.mark.parametrize(
    "text,expected",
    [
        ("mail me at dana.reyes@example.org today", ("EMAIL", "dana.reyes@example.org")),
        ("call (617) 555-0142 please", ("PHONE", "(617) 555-0142")),
        ("ring +44 20 7946 0958 after six", ("PHONE", "+44 20 7946 0958")),
        ("card 4242 4242 4242 4242 exp 08/28", ("CARD", "4242 4242 4242 4242")),
        ("IBAN GB82 WEST 1234 5698 7654 32 thanks", ("IBAN", "GB82 WEST 1234 5698 7654 32")),
        ("routing number 021000021 for the transfer", ("ROUTING", "021000021")),
        ("my SSN is 123-45-6789", ("SSN", "123-45-6789")),
        ("ssn: 123456789", ("SSN", "123456789")),
        ("Your verification code is 482913.", ("OTP", "482913")),
        ("482913 is your Acme login code", ("OTP", "482913")),
        ("Enter 4821 to verify your phone", ("OTP", "4821")),
        ("password: hunter2!x", ("PASSWORD", "hunter2!x")),
        ("server at 10.0.12.7 is down", ("IP_ADDRESS", "10.0.12.7")),
        ("see https://docs.acme.com/a/b?id=99 now", ("URL", "https://docs.acme.com/a/b?id=99")),
        ("on 2026-03-12 we ship", ("DATE", "2026-03-12")),
        ("on March 12, 2026 we ship", ("DATE", "March 12, 2026")),
        ("due 12 Mar 2026", ("DATE", "12 Mar 2026")),
        ("it cost $1,234.50 in total", ("MONEY", "$1,234.50")),
        ("send it to 221 Baker Street, Apt 4 by noon", ("ADDRESS", "221 Baker Street, Apt 4")),
        ("signed with Northwind Traders Inc. last week", ("ORG", "Northwind Traders Inc.")),
        ("Hi Dana,\nthanks", ("PERSON", "Dana")),
        ("I will meet Dana Reyes at noon", ("PERSON", "Dana Reyes")),
        ("From: Dana Reyes <x@example.org>", ("PERSON", "Dana Reyes")),
        ("Thanks,\nSam Okafor\n", ("PERSON", "Sam Okafor")),
        ("ask Dr. Priya Raman", ("PERSON", "Priya Raman")),
        ("key sk-proj-abcdefghijklmnopqrstuvwx123 leaked", ("API_KEY", "sk-proj-abcdefghijklmnopqrstuvwx123")),
    ],
)
def test_finds(text, expected):
    assert expected in found(text)


@pytest.mark.parametrize(
    "text",
    [
        "order 4242 4242 4242 4241 shipped",  # fails Luhn
        "tracking 123456789 arrives",  # nine digits, no SSN or routing cue
        "IBAN GB00 WEST 1234 5698 7654 32",  # bad check digits
        "meet in New York tomorrow",  # a place, not a person
        "see you on February 30, 2026",  # not a real day
        "version 3.2.1 is out",  # not an IP (only three parts)
        "the code review is at 10",  # 'code' without digits right after
        "SSN 666-12-3456",  # area 666 is never issued
    ],
)
def test_ignores_lookalikes(text):
    types = {t for t, _ in found(text)}
    assert not types & {"CARD", "SSN", "IBAN", "PERSON", "DATE", "IP_ADDRESS", "OTP"}, found(text)


def test_password_link_is_not_a_password():
    assert ("PASSWORD", "https://acme.com/reset") not in found("password: https://acme.com/reset")


def test_known_values_win_over_patterns():
    s = Session("strict", known={"PERSON": ["Iris Chen"]})
    assert ("PERSON", "Iris Chen") in found("lunch with Iris Chen", s)


def test_known_digits_match_any_layout():
    det = KnownDetector([("PHONE", "6175550142", "digits")])
    spans = det.detect("ring 617.555.0142 or (617) 555 0142")
    assert [s.text for s in spans] == ["617.555.0142", "(617) 555 0142"]


def test_resolve_prefers_priority_then_length():
    a = Span(0, 10, "EMAIL", "x" * 10, priority=85)
    b = Span(0, 4, "PERSON", "xxxx", priority=40)
    c = Span(2, 12, "PHONE", "y" * 10, priority=68)
    assert resolve([b, c, a]) == [a]


def test_allow_list_keeps_values_visible():
    s = Session("strict", allow=["Northwind Traders Inc."])
    assert not found("signed with Northwind Traders Inc. today", s)
