"""The benchmark's data: fictional, generated from a fixed seed, with every planted value labelled.

Nothing here is real. Names come from a list that does not overlap the library's fake pools, so a leak is always
unambiguous: if one of these names shows up in what the model saw, it leaked.

Each item is {"id", "kind", "text", "gold": [[type, value], ...], "task": {...}} where `task` (when present) has a
question with an exact answer, so a model run can be scored without a judge model.
"""

from __future__ import annotations

import datetime as dt
import json
import random
import re
from pathlib import Path

PEOPLE = [("Ana", "Whitfield", "f"), ("Bilal", "Okonkwo", "m"), ("Carmen", "Ruiz", "f"), ("Dev", "Malhotra", "m"),
          ("Erin", "Castellano", "f"), ("Femi", "Adebayo", "m"), ("Grace", "Lindholm", "f"), ("Hassan", "Rahimi", "m"),
          ("Isla", "Fairbanks", "f"), ("Jonah", "Weissman", "m"), ("Keiko", "Morita", "f"), ("Luis", "Aranda", "m"),
          ("Mona", "Sorensen", "f"), ("Nikolai", "Volkov", "m"), ("Olivia", "Brandt", "f"), ("Pedro", "Salgado", "m")]
COMPANIES = ["Greybridge Logistics", "Pinehurst Dental", "Tallow & Reed", "Brightmoor Bank", "Quillfeather Press"]
STREETS = ["Linden Avenue", "Harbor Road", "Elm Street", "Ridgeway Drive", "Chestnut Lane"]
WEEKDAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]


def luhn_complete(prefix: str) -> str:
    for d in "0123456789":
        s = prefix + d
        total = sum(int(c) if i % 2 == 0 else (int(c) * 2 - 9 if int(c) * 2 > 9 else int(c) * 2)
                    for i, c in enumerate(reversed(s)))
        if total % 10 == 0:
            return s
    raise AssertionError


def make(n: int = 120, seed: int = 20261105) -> list[dict]:
    rng = random.Random(seed)
    items = []
    for i in range(n):
        a, b = rng.sample(PEOPLE, 2)
        name_a, name_b = f"{a[0]} {a[1]}", f"{b[0]} {b[1]}"
        email_a = f"{a[0].lower()}.{a[1].lower()}@{rng.choice(['mailhub.com', 'postbox.net', 'inboxly.org'])}"
        phone = f"({rng.choice(['617', '312', '646', '415'])}) {rng.randint(200, 999)}-{rng.randint(1000, 9999)}"
        day = dt.date(2026, 1, 5) + dt.timedelta(days=rng.randint(0, 300))
        date_txt = day.strftime("%B ") + str(day.day) + day.strftime(", %Y")
        otp = str(rng.randint(100000, 999999))
        card = luhn_complete("4" + "".join(str(rng.randint(0, 9)) for _ in range(14)))
        card_txt = " ".join(card[k:k + 4] for k in range(0, 16, 4))
        amount_a, amount_b = rng.randint(20, 900), rng.randint(20, 900)
        company = rng.choice(COMPANIES)
        street = f"{rng.randint(10, 999)} {rng.choice(STREETS)}"
        kind = ["email", "chat", "tool_result", "invoice"][i % 4]
        if kind == "email":
            text = (f"From: {name_a} <{email_a}>\nHi {b[0]},\n\nCan we meet on {date_txt}? Call me at {phone}.\n"
                    f"Your verification code is {otp}.\n\nThanks,\n{a[0]}")
            gold = [["PERSON", name_a], ["EMAIL", email_a], ["PERSON", b[0]], ["DATE", date_txt], ["PHONE", phone],
                    ["OTP", otp], ["PERSON", a[0]]]
            task = {"q": "On which weekday is the proposed meeting? Answer with the weekday name only.",
                    "answer": WEEKDAYS[day.weekday()], "scored_as": "exact"}
        elif kind == "chat":
            text = (f"I need to pay {name_b} back. Use my card {card_txt}. Dinner was ${amount_a}.00 and "
                    f"the taxi was ${amount_b}.00. Ship the receipt to {street}.")
            gold = [["PERSON", name_b], ["CARD", card_txt], ["MONEY", f"${amount_a}.00"], ["MONEY", f"${amount_b}.00"],
                    ["ADDRESS", street]]
            task = {"q": "What is the total of the two amounts? Answer with the number only, like 123.00.",
                    "answer": f"{amount_a + amount_b}.00", "scored_as": "money"}
        elif kind == "tool_result":
            text = json.dumps({"results": [
                {"name": name_a, "email": email_a, "role": "approver"},
                {"name": name_b, "phone": phone, "role": "requester"}]})
            gold = [["PERSON", name_a], ["EMAIL", email_a], ["PERSON", name_b], ["PHONE", phone]]
            task = {"q": "Who is the approver? Answer with the full name only.", "answer": name_a,
                    "scored_as": "exact"}
        else:
            text = (f"Invoice from {company} to {name_a}, {street}.\nDue {date_txt}. Amount ${amount_a}.00.\n"
                    f"Questions: {email_a}")
            gold = [["ORG", company], ["PERSON", name_a], ["ADDRESS", street], ["DATE", date_txt],
                    ["MONEY", f"${amount_a}.00"], ["EMAIL", email_a]]
            task = {"q": "Who is the invoice addressed to? Answer with the full name only.", "answer": name_a,
                    "scored_as": "exact"}
        items.append({"id": f"gen-{i:03d}", "kind": kind, "text": text, "gold": gold, "task": task,
                      "known": {"ORG": [company]}})
    return items


_MARK = re.compile(r"\[\[([A-Z_]+):(.+?)\]\]")


def load_handwritten(path: Path | None = None) -> list[dict]:
    """Hand-written items, marked inline like [[PERSON:Ana Whitfield]], parsed into text plus gold labels."""
    path = path or Path(__file__).with_name("handwritten.txt")
    items = []
    for i, block in enumerate(path.read_text(encoding="utf-8").split("\n---\n")):
        block = "\n".join(line for line in block.split("\n") if not line.startswith("#")).strip("\n")
        if not block:
            continue
        gold = [[m[1], m[2]] for m in _MARK.finditer(block)]
        items.append({"id": f"hand-{i:03d}", "kind": "handwritten", "text": _MARK.sub(lambda m: m[2], block),
                      "gold": gold, "task": None, "known": {}})
    return items
