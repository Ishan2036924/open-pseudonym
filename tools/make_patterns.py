"""Writes data/patterns.json, the detection patterns every SDK loads.

Patterns live in one JSON file so the Python and TypeScript SDKs can never drift apart. To keep Python's `re` and
JavaScript's `RegExp` (with the u flag) agreeing on every match we stick to a small common subset:

  - [0-9] instead of \\d, explicit letter ranges instead of \\w, and no \\s (we spell out the whitespace we mean)
  - no \\b: word edges are written as lookarounds against [A-Za-z0-9_]
  - no named groups; the value we want is the capture group given in `group`
  - the only flag is "i"

Run it after editing a pattern, then run the vectors in both SDKs.
"""

import json
import re
from pathlib import Path

NB = "(?<![A-Za-z0-9_])"  # no word character right before
NA = "(?![A-Za-z0-9_])"  # no word character right after
NOT_WS = "[^ \\t\\r\\n\\f\\v]"
UP = "A-ZÀ-ÖØ-Þ"
LO = "a-zß-öø-ÿ"
# a capitalised word, also O'Neil, D'Angelo and Mary-Jane
NAME = f"[{UP}][{LO}]*(?:'[{UP}])?[{LO}]+(?:-[{UP}]?[{LO}]+)?"
FULL = f"{NAME}(?: {NAME}){{0,2}}"
MON = (
    "(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|June?|July?|Aug(?:ust)?|Sep(?:t(?:ember)?)?"
    "|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)"
)
# full words never take a dot; abbreviations may ("St."), so a sentence-ending "Road." keeps its full stop
SUFFIX = (
    "Street|Avenue|Road|Lane|Drive|Boulevard|Way|Court|Place|Terrace|Parkway|Highway|Square"
    "|(?:St|Ave|Rd|Ln|Dr|Blvd|Ct|Pl|Pkwy|Hwy|Sq)\\.?"
)
OCTET = "(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"

# Wider letter sets for the word-list patterns, so "Łukasz Nowak" and "Nguyễn Văn An" are words too. The older cue
# patterns keep the narrower sets above.
UPX = UP + "ĀĂĄĆĈĊČĎĐĒĔĖĘĚĜĞĠĢĤĦĨĪĬĮİĴĶĹĻĽĿŁŃŅŇŌŎŐŒŔŖŘŚŜŞŠŢŤŦŨŪŬŮŰŲŴŶŸŹŻŽ"
LOX = LO + "ā-žạ-ỹ"
NBX = f"(?<![A-Za-z0-9_À-ÖØ-öø-ÿĀ-žẠ-ỹ])"
NAX = f"(?![A-Za-z0-9_À-ÖØ-öø-ÿĀ-žẠ-ỹ])"
NAMEX = f"[{UPX}][{LOX}]*(?:'[{UPX}])?[{LOX}]+(?:-[{UPX}]?[{LOX}]+)?"
POOLS = json.loads((Path(__file__).resolve().parent.parent / "data" / "pools.json").read_text(encoding="utf-8"))


def esc(ch: str) -> str:
    # only the characters that are syntax in both engines; JavaScript's u flag rejects any other escape
    return "\\" + ch if ch in "^$\\.*+?()[]{}|/" else ch


def trie(items) -> str:
    """One regex that matches any of the items, built as a tree of shared prefixes. A flat alternation of a
    thousand names would be tried one by one at every position; a tree decides in a few steps."""
    root: dict = {}
    for item in items:
        node = root
        for ch in item:
            node = node.setdefault(ch, {})
        node[""] = {}

    def build(node: dict) -> str:
        alts = [esc(k) + build(node[k]) for k in sorted(k for k in node if k)]
        if not alts:
            return ""
        body = alts[0] if len(alts) == 1 and len(alts[0]) == 1 else "(?:" + "|".join(alts) + ")"
        return body + "?" if "" in node else body

    return "(?:" + build(root) + ")"


def cased(name: str) -> list[str]:
    """How a lower-case list entry is written as a name: "ji-woo" as "Ji-woo" and "Ji-Woo"."""
    first = name[:1].upper() + name[1:]
    parts = first.split("-")
    return sorted({first, "-".join(p[:1].upper() + p[1:] for p in parts)})


AMBIGUOUS = {a.lower() for a in POOLS["ambiguous_names"]}
GIVEN = trie(v for n in POOLS["name_gender"] if n not in AMBIGUOUS for v in cased(n))
ANY_GIVEN = trie(v for n in POOLS["name_gender"] for v in cased(n))
STOP = trie(POOLS["name_stopwords"]) + NAX
# words that start sentences and should never be swallowed into a name, a place or an organisation in front of them
LEAD = trie("The This That These Those A An And But Or If So Then When While Yesterday Today Tomorrow Our My Your "
            "Their His Her Its We I You They He She It At In On From To For With Please Thanks Hi Hello Dear "
            "Also Meanwhile Last Next Every Each".split()) + NAX
PARTICLES = "(?:de|del|della|da|das|dos|du|di|van|von|der|den|ter|ten|bin|ibn|al|el|la|le|zu)"
PLACES = POOLS["places"]
AMBIGUOUS_PLACES = set(POOLS["ambiguous_places"])
STATE_CODES = trie(POOLS["us_state_codes"])
STATE_NAMES = trie(n for n, (kind, _) in PLACES.items() if kind == "state")
PLACE_CUE = (
    "(?:[Ii]n|[Nn]ear|[Aa]round|[Oo]utside|[Ii]nside|[Aa]cross|[Tt]hroughout|[Vv]isit(?:s|ed|ing)?|[Tt]owards?"
    "|(?:[Mm]ov(?:e|ed|ing)|[Ff]l(?:y|ew|ying)|[Dd]r(?:ive|ove|iving)|[Tt]rip|[Tt]ravel(?:s|ed|led|ing|ling)?"
    "|[Rr]elocat(?:e|ed|ing)|[Hh]ead(?:ed|ing)|[Rr]eturn(?:s|ed|ing)?|[Bb]ack|[Ww]ent|[Gg]oing) to"
    "|(?:[Ii]s|[Aa]re|[Aa]m|[Ww]as|[Ww]ere|[Cc]omes?|[Cc]ame|[Hh]ails?|[Hh]ailed|[Oo]riginally) from"
    "|[Bb]ased (?:in|out of))"
)
INSTITUTIONS = trie(
    "Hospital Clinic University College Academy Institute Bank Church Foundation Group Labs Laboratories Partners "
    "Associates Holdings Technologies Solutions Agency Council Ministry Department Center Centre Health Healthcare "
    "Pharmacy Hotel Restaurant Cafe Café Bakery Studio Studios Consulting Capital Ventures Insurance Motors Airlines "
    "Airways Logistics Systems Software Media Publishing Press Trust Society Club Library Museum Gallery Theatre "
    "Theater Stadium Arena Market Store Salon Spa Gym Fitness Dental Pediatrics".split()
)
ORGTOK = f"[{UPX}][A-Za-zÀ-ÿĀ-ž&'.-]*"  # inside a name a dot is fine ("St. Mary's")
ORGEND = f"[{UPX}][A-Za-zÀ-ÿĀ-ž&'-]*[A-Za-zÀ-ÿĀ-ž]"  # the last word never takes the full stop after it

patterns = []


def add(type_, pattern, group=0, flags="", check=None, priority=50, note=""):
    re.compile(pattern, re.I if "i" in flags else 0)  # fail here, not at runtime
    patterns.append(
        {"type": type_, "pattern": pattern, "group": group, "flags": flags, "check": check, "priority": priority,
         "note": note}
    )


# Secrets first: they have the most distinctive shapes and the highest cost if missed.
add("API_KEY", "-----BEGIN [A-Z ]*PRIVATE KEY-----[^]*?-----END [A-Z ]*PRIVATE KEY-----".replace("[^]", "[\\s\\S]"),
    priority=95, note="PEM private key block")
add("API_KEY",
    NB + "((?:sk-(?:proj-|ant-[a-z0-9]+-)?|sk_live_|sk_test_|rk_live_|rk_test_|ghp_|gho_|ghs_|github_pat_|glpat-"
    "|xox[abprs]-|hf_|AKIA|ASIA|AIza)[A-Za-z0-9_-]{16,})" + NA,
    group=1, priority=90, note="well-known key prefixes")
add("API_KEY", NB + "(eyJ[A-Za-z0-9_-]{8,}\\.eyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,})" + NA, group=1, priority=90,
    note="JSON web token")
# lengths are bounded (RFC 5321: 64 for the local part, 63 per label) so a long run without an @ stays linear
add("EMAIL", NB + "([A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\\.[A-Za-z0-9-]{1,63}){0,8}\\.[A-Za-z]{2,24})" + NA,
    group=1, priority=85)
add("URL", "(https?://[^ \\t\\r\\n\\f\\v<>\"'`]+[^ \\t\\r\\n\\f\\v<>\"'`.,;:!?)\\]}])", group=1, priority=84)
CODE = trie(POOLS["code_mentions"])
add("USERNAME",
    "(?<![A-Za-z0-9_.@/+-])(@(?!" + CODE + "(?![A-Za-z0-9_]))[A-Za-z_](?:[A-Za-z0-9_.]{0,28}[A-Za-z0-9_])?)"
    "(?![A-Za-z0-9_@])",
    group=1, priority=58, note="an @handle; common code annotations such as @property are not people")
add("IBAN", NB + "([A-Z]{2}[0-9]{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?)" + NA, group=1, check="iban",
    priority=82)
add("CARD", "(?<![0-9])((?:[0-9][ -]?){12,18}[0-9])(?![0-9])", group=1, check="card", priority=81)
add("SSN", "(?<![0-9-])([0-9]{3}-[0-9]{2}-[0-9]{4})(?![0-9-])", group=1, check="ssn", priority=80)
add("SSN",
    NB + "(?:ssn|social security(?: number| no\\.?)?)[^0-9\\n]{0,12}?([0-9]{9}|[0-9]{3} [0-9]{2} [0-9]{4})(?![0-9])",
    group=1, flags="i", check="ssn", priority=80, note="bare nine digits only right after an SSN cue")
add("ROUTING", NB + "(?:routing|aba|rtn)[^0-9\\n]{0,30}?([0-9]{9})(?![0-9])", group=1, flags="i", check="aba",
    priority=79)
add("BANK_ACCOUNT", NB + "(?:account|acct)(?: number| no\\.?| #|#)?[^0-9\\n]{0,6}?([0-9]{6,17})(?![0-9])", group=1,
    flags="i", priority=78)
add("OTP",
    NB + "(?:verification|security|login|sign[- ]?in|one[- ]time|confirmation|access|2fa|auth(?:entication)?)?"
    " ?(?:code|passcode|otp|pin)(?: is| was|:| =)? ?([0-9]{4,8}|[0-9]{3} [0-9]{3})(?![0-9])",
    group=1, flags="i", priority=76)
add("OTP", "(?<![0-9])([0-9]{4,8})(?![0-9]) is your [A-Za-z ]{0,30}?(?:code|passcode|otp|pin)", group=1, flags="i",
    priority=76)
add("OTP", NB + "(?:enter|use|type) ([0-9]{4,8})(?![0-9]) to (?:verify|confirm|continue|sign in|log in)", group=1,
    flags="i", priority=76)
add("PASSWORD",
    NB + "(?:password|passwd|pwd|passphrase)(?: is:?|:| =)[ \\t]*(?!https?://)(" + NOT_WS + "{4,64})",
    group=1, flags="i", priority=75)
add("IP_ADDRESS", f"(?<![0-9.])({OCTET}(?:\\.{OCTET}){{3}})(?![0-9.])", group=1, priority=70)
add("PHONE", "(?<![0-9+])((?:\\+?1[ .-]?)?\\(?[2-9][0-9]{2}\\)?[ .-][0-9]{3}[ .-][0-9]{4})(?![0-9])", group=1,
    check="phone", priority=68, note="North American numbers, separators required")
add("PHONE", "(?<![0-9+])(\\+[1-9][0-9]{0,2}(?:[ .-]?\\(?[0-9]{1,4}\\)?){2,5}[0-9])(?![0-9])", group=1,
    check="phone", priority=67, note="international numbers that start with +")
add("DATE", "(?<![0-9])([0-9]{4}-[0-9]{2}-[0-9]{2})(?![0-9])", group=1, check="date", priority=60,
    note="ISO 2026-03-05")
add("DATE", "(?<![0-9/])([0-9]{1,2}/[0-9]{1,2}/[0-9]{4})(?![0-9/])", group=1, check="date", priority=60,
    note="03/05/2026, month first unless the session says day first")
add("DATE", NB + "(" + MON + "\\.? [0-9]{1,2}(?:st|nd|rd|th)?(?:, [0-9]{4})?)" + NA, group=1, check="date",
    priority=60, note="March 5, 2026 or March 5")
add("DATE", NB + "([0-9]{1,2}(?:st|nd|rd|th)? " + MON + "\\.?(?: [0-9]{4})?)" + NA, group=1, check="date",
    priority=60, note="5 March 2026")
add("MONEY", "([$€£] ?[0-9]{1,3}(?:,[0-9]{3})+(?:\\.[0-9]{2})?|[$€£] ?[0-9]+(?:\\.[0-9]{2})?)(?![0-9])", group=1,
    priority=55)
add("MONEY", NB + "([0-9]{1,3}(?:,[0-9]{3})*(?:\\.[0-9]{2})? ?(?:USD|EUR|GBP|dollars|euros))" + NA, group=1,
    priority=55)
add("ADDRESS",
    NB + f"([0-9]{{1,6}}[A-Z]? (?:[{UP}][{LO}]+ ){{1,3}}(?:{SUFFIX})(?:,? (?:Apt|Apartment|Suite|Ste|Unit|#)"
    " ?[A-Za-z0-9-]+)?)" + NA,
    group=1, priority=52)
add("ADDRESS", NB + "([A-Z]{1,2}[0-9][A-Z0-9]? [0-9][ABD-HJLNP-UW-Z]{2})" + NA, group=1, priority=53,
    note="UK postcode")
add("ADDRESS", NB + "([ABCEGHJ-NPRSTVXY][0-9][ABCEGHJ-NPRSTV-Z] ?[0-9][ABCEGHJ-NPRSTV-Z][0-9])" + NA, group=1,
    priority=53, note="Canadian postal code")
add("ADDRESS", NB + "(?:" + STATE_CODES + "|" + STATE_NAMES + "|[Zz][Ii][Pp](?: [Cc]ode)?:?|ZIP(?: [Cc]ode)?:?"
    "|[Pp]ostal [Cc]ode:?),? ([0-9]{5}(?:-[0-9]{4})?)(?![0-9])", group=1, priority=53,
    note="US ZIP code after a state or a zip cue")
# Record numbers. A cue word in front, at least five characters, at least one digit.
ID_VALUE = "((?=[A-Za-z0-9-]*[0-9])[A-Za-z0-9][A-Za-z0-9-]{4,24})"
# the value holds a letter or a dash too, so "order 10000 units" stays a quantity
ID_MIXED = "((?=[A-Za-z0-9-]*[0-9])(?=[0-9]*[A-Za-z-])[A-Za-z0-9][A-Za-z0-9-]{4,24})"
ID_MARK = "(?: number| no\\.?| num| #| id)"
add("ID",
    NB + "(?:customer|cust|client|member(?:ship)?|employee|emp|staff|student|patient|mrn|medical record|passport"
    "|licen[cs]e|driver'?s licen[cs]e|driving licen[cs]e|national id|user id|tracking|shipment)"
    + ID_MARK + "?[ :#.-]{0,3}" + ID_VALUE + NA,
    group=1, flags="i", priority=54, note="a record number after a cue that only ever names a record")
add("ID",
    NB + "(?:order|case|ticket|invoice|claim|policy|reference|ref|booking|reservation|confirmation|record|id)"
    "(?:" + ID_MARK + "[ :#.-]{0,3}|[ ]?[:#][ ]?)" + ID_VALUE + NA,
    group=1, flags="i", priority=54, note="after a cue that can also mean something else, only with a marker")
add("ID",
    NB + "(?:order|case|ticket|invoice|claim|policy|reference|ref|booking|reservation|confirmation|record|id) "
    + ID_MIXED + NA,
    group=1, flags="i", priority=54, note="or when the value mixes letters, digits and dashes")
add("ID",
    NB + "((?!(?:CVE|GHSA|ISO|RFC|SHA|UTF|COVID|PEP|JSR|CWE|NIST|SP|IEEE|ECMA|TLS|HTTP|AES|MD|RSA|SKU|ASCII|IPV)-)"
    "[A-Z]{2,6}-(?=[0-9-]*[0-9]{4})[0-9]{2,12}(?:-[0-9A-Z]{1,12}){0,2})" + NA,
    group=1, priority=55, note="prefixed record numbers such as CUST-00921; standards and CVE ids are left alone")
add("ORG", NB + f"((?:[{UP}][A-Za-zÀ-ÿ&]+ ){{1,4}}(?:Inc|LLC|Ltd|Corp|Corporation|GmbH|PLC|LLP|Co)\\.?)" + NA,
    group=1, priority=45)
add("ORG", NBX + "(" + trie(POOLS["org_names"]) + ")" + NAX, group=1, priority=46,
    note="companies named after people, so they are not taken for a person")
add("ORG", NBX + "((?!" + LEAD + ")(?!" + STOP + ")" + ORGTOK + "(?: " + ORGTOK + "){0,3} " + INSTITUTIONS + ")" + NAX,
    group=1, priority=45, note="hospitals, banks, universities and the like")
add("ORG", NBX + "(" + INSTITUTIONS + " of (?:the )?" + ORGEND + "(?: " + ORGEND + "){0,2})" + NAX, group=1,
    priority=45, note="Bank of America, University of Washington")
# Places. Names that are also people or words (Austin, Jackson, Bath) only count after a place cue.
add("LOCATION", NBX + "(" + trie(p for p in PLACES if p not in AMBIGUOUS_PLACES) + ")" + NAX, group=1, priority=37,
    note="countries, states, regions and large cities")
add("LOCATION", NBX + PLACE_CUE + " (" + trie(AMBIGUOUS_PLACES) + ")" + NAX, group=1, priority=37,
    note="places that are also names or words, after a place cue")
add("LOCATION", NBX + "((?!" + LEAD + ")(?:" + NAMEX + " ){0,2}" + NAMEX + ", (?:" + STATE_CODES + "|" + STATE_NAMES
    + "))" + NAX, group=1, priority=35, note="Smalltown, MT: a town the list does not know, with its state")
# People. Without a language model we only trust a capitalised name when something around it says "this is a
# person": a greeting, a title, a mail header, a sign-off, or a verb that usually takes a person.
add("PERSON", f"(?:^|\\n)[ \\t]*(?:[Hh]i|[Hh]ello|[Hh]ey|[Dd]ear|[Gg]ood (?:morning|afternoon|evening)|[Hh]ola|[Bb]onjour|[Ss]alut|[Hh]allo|[Cc]iao|[Oo]lá|[Oo]i|[Nn]amaste|[Mm]erhaba|[Hh]ej)[ ,]+({FULL})"
    "(?=[,!.\\n:]|$)", group=1, check="name", priority=40, note="greetings, in either case, in several languages")
add("PERSON", f"(?:Mr|Mrs|Ms|Mx|Dr|Prof)\\.? ({FULL})" + NA, group=1, check="name", priority=40)
add("PERSON", f"(?:^|\\n)(?:From|To|Cc|Bcc|Reply-To): *({FULL}) *(?=<|,|\\n|$)", group=1, check="name", priority=40,
    note="mail headers, with or without the address")
add("PERSON",
    f"(?:^|\\n)[ \\t]*(?:Thanks|Thank you|Best|Regards|Best regards|Kind regards|Cheers|Sincerely|Warmly),?[ \\t]*\\n"
    f"[ \\t]*({FULL})[ \\t]*(?=\\n|$)",
    group=1, check="name", priority=40, note="sign-off on its own line")
add("PERSON", f"(?:^|\\n|[.!?] )[ \\t]*(?:[Tt]hanks|[Tt]hank you|[Cc]heers),? ({FULL})(?=[,!.\\n]| for|$)", group=1,
    check="name", priority=40, note="thanks inline")
add("PERSON",
    '"(?:name|full_name|fullName|display_name|displayName|contact|contact_name|customer|customer_name|recipient'
    '|sender|requester|approver|owner|assignee|author|attendee|patient|client)" ?: ?"(' + FULL + ')"',
    group=1, check="name", priority=40, note="a name field in JSON (tool results)")
add("PERSON",
    NB + "(?:with|meet|meeting|ask|call|email|cc|tell|invite|from|for|and|by|pay|paid|text|message|ping|remind"
    "|introduce|contact|thank|reply to|send to|sent to|forward to|write to|addressed to) (" + NAME + " " + NAME + ")" + NA,
    group=1, check="name", priority=39)
add("PERSON",
    NB + "(?:[Pp]atient|[Cc]lient|[Cc]ustomer|[Ee]mployee|[Tt]enant|[Aa]pplicant|[Cc]andidate|[Gg]uest|[Mm]ember"
    "|[Rr]esident|[Oo]wner)(?: name)?:? (" + NAME + " " + NAME + ")" + NA,
    group=1, check="name", priority=39, note="a role word before a full name, as in records and forms")
add("PERSON", f"(?:^|[ (])to ({NAME} {NAME})(?=,)", group=1, check="name", priority=38,
    note="'to Ana Whitfield,' as in an address line")
# A given name from the word list needs no cue. It takes up to two more capitalised words as the surname (with an
# optional middle initial and particles such as "de la" or "van"), but never a stopword ("Sam Patel From Acme").
add("PERSON",
    NBX + "(" + GIVEN + "(?:(?: [" + UPX + "]\\.)? (?:" + PARTICLES + " ){0,2}(?!" + STOP + ")" + NAMEX + "){0,2})"
    + NAX, group=1, check="name", priority=36, note="a known given name, with the surname that follows")
add("PERSON",
    NBX + "((?:" + trie(POOLS["family_first"]) + ")(?: (?:" + "|".join(POOLS["middle_names"]) + "))? " + ANY_GIVEN
    + "|" + trie(POOLS["family_first_words"]) + " " + GIVEN + ")" + NAX,
    group=1, priority=36, note="family name first, as in Zhang Wei or Nguyễn Văn An")

if __name__ == "__main__":
    out = Path(__file__).resolve().parent.parent / "data" / "patterns.json"
    doc = {"version": 1, "note": "Detection patterns shared by every SDK. See spec section 4.", "patterns": patterns}
    out.write_text(json.dumps(doc, indent=1, ensure_ascii=False) + "\n")
    print(f"wrote {len(patterns)} patterns to {out}")
