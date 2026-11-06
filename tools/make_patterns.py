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
add("ORG", NB + f"((?:[{UP}][A-Za-zÀ-ÿ&]+ ){{1,4}}(?:Inc|LLC|Ltd|Corp|Corporation|GmbH|PLC|LLP|Co)\\.?)" + NA,
    group=1, priority=45)
# People. Without a language model we only trust a capitalised name when something around it says "this is a
# person": a greeting, a title, a mail header, a sign-off, or a verb that usually takes a person.
add("PERSON", f"(?:^|\\n)[ \\t]*(?:[Hh]i|[Hh]ello|[Hh]ey|[Dd]ear|[Gg]ood (?:morning|afternoon|evening))[ ,]+({FULL})"
    "(?=[,!.\\n:]|$)", group=1, check="name", priority=40, note="greetings, in either case")
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

if __name__ == "__main__":
    out = Path(__file__).resolve().parent.parent / "data" / "patterns.json"
    doc = {"version": 1, "note": "Detection patterns shared by every SDK. See spec section 4.", "patterns": patterns}
    out.write_text(json.dumps(doc, indent=1, ensure_ascii=False) + "\n")
    print(f"wrote {len(patterns)} patterns to {out}")
