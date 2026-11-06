"""Realistic stand-ins ("surrogates"), one maker per type.

The rules that matter (spec section 7):
  - A fake is chosen at random from a pool, not computed from the real value, so it says nothing about it.
  - The same real value always gets the same fake within a vault, and so do its parts: "Dana Reyes" -> "Maya Ortiz",
    later "Dana" -> "Maya", and dana.reyes@... -> maya.ortiz@...
  - Fakes come from ranges set aside for examples wherever such ranges exist (.example domains, 555-01xx phone
    numbers, documentation IP blocks, published test cards, advertising SSNs), so a fake that leaks into a real
    action cannot reach a real person.
  - A fake never equals a real value we have seen, and never appears elsewhere in the text being masked.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from . import checks
from ._data import pools
from .types import digits_of
from .vault import Vault

UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
LOWER = "abcdefghijklmnopqrstuvwxyz"
DIGITS = "0123456789"

KEY_PREFIXES = sorted(
    ["sk-proj-", "sk-ant-", "sk-", "sk_live_", "sk_test_", "rk_live_", "rk_test_", "ghp_", "gho_", "ghs_",
     "github_pat_", "glpat-", "xoxa-", "xoxb-", "xoxp-", "xoxr-", "xoxs-", "hf_", "AKIA", "ASIA", "AIza"],
    key=lambda p: -len(p),
)
GENERIC_MAILBOXES = {
    "info", "support", "sales", "hello", "contact", "admin", "noreply", "no", "reply", "team", "billing", "help",
    "office", "hr", "jobs", "careers", "news", "newsletter", "notifications", "mail", "accounts", "security",
    "service", "orders", "do", "not",
}
GENERIC_SUBDOMAINS = {"www", "docs", "mail", "app", "login", "api", "blog", "shop", "support", "help", "m", "accounts",
                      "auth", "id", "portal", "my"}
TWO_PART_SUFFIXES = {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz", "co.jp", "co.in",
                     "com.br", "com.mx", "co.za", "com.sg", "com.cn", "com.tr", "co.kr"}
AREA_CODES = ["201", "212", "312", "415", "512", "617", "720", "206", "305", "404"]
TEST_NETS = ["192.0.2.", "198.51.100.", "203.0.113."]
ORG_SUFFIX = re.compile(r" (Inc|LLC|Ltd|Corp|Corporation|GmbH|PLC|LLP|Co)(\.?)$")
ADDRESS_PARTS = re.compile(
    r"^([0-9]+)([A-Z]?) (.+?) (Street|St|Avenue|Ave|Road|Rd|Lane|Ln|Drive|Dr|Boulevard|Blvd|Way|Court|Ct|Place|Pl"
    r"|Terrace|Parkway|Pkwy|Highway|Hwy|Square|Sq)(\.?)(.*)$"
)
URL_PARTS = re.compile(r"^(https?://)([^/?#:]+)(:[0-9]+)?(.*)$", re.IGNORECASE)


@dataclass
class Ctx:
    """What a maker needs besides the real value."""

    vault: Vault
    text: str  # the text being masked, so a fake never collides with something already in it
    options: dict

    def free(self, candidate: str) -> bool:
        low = candidate.lower()
        if low in self.vault.used or low in self.vault.real_seen:
            return False
        return re.search(r"(?<![A-Za-z0-9_])" + re.escape(candidate) + r"(?![A-Za-z0-9_])", self.text,
                         re.IGNORECASE) is None


def pick(ctx: Ctx, label: str, pool: list[str]) -> str:
    """Draw from a pool until we hit a free value. If the pool runs dry, pair two values with a hyphen."""
    for _ in range(3 * len(pool)):
        c = pool[ctx.vault.drbg.below(label, len(pool))]
        if ctx.free(c):
            return c
    for _ in range(200):
        a = pool[ctx.vault.drbg.below(label, len(pool))]
        b = pool[ctx.vault.drbg.below(label, len(pool))]
        c = f"{a}-{b}"
        if ctx.free(c):
            return c
    raise RuntimeError(f"ran out of fake values for {label}")


def chars(ctx: Ctx, label: str, alphabet: str, n: int) -> str:
    return "".join(alphabet[ctx.vault.drbg.below(label, len(alphabet))] for _ in range(n))


def shape(ctx: Ctx, value: str, label: str = "shape") -> str:
    """Same length, same kind of character in each place: 'Ab3-x9' -> 'Qx7-k2'."""
    out = []
    for ch in value:
        if "A" <= ch <= "Z":
            out.append(chars(ctx, label, UPPER, 1))
        elif "a" <= ch <= "z":
            out.append(chars(ctx, label, LOWER, 1))
        elif "0" <= ch <= "9":
            out.append(chars(ctx, label, DIGITS, 1))
        else:
            out.append(ch)
    return "".join(out)


def styled(fake: str, like: str) -> str:
    """Copy the capitalisation style of the real token onto the fake."""
    if len(like) > 1 and like.isupper():
        return fake.upper()
    if like.islower():
        return fake.lower()
    return fake


def fill_template(template: str, digits: str) -> str:
    """Put new digits where the old ones were, keeping spaces, dashes and brackets."""
    if len(digits_of(template)) != len(digits):
        return digits
    it = iter(digits)
    return "".join(next(it) if "0" <= ch <= "9" else ch for ch in template)


def registrable(host: str) -> str:
    labels = host.lower().rstrip(".").split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in TWO_PART_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


# People, organisations, places

def _gender(token: str) -> str:
    return pools()["name_gender"].get(token.lower().split("-")[0], "n")


def person(ctx: Ctx, real: str) -> str:
    tokens = real.split()
    names = pools()["first_names"]
    keep_gender = ctx.options.get("keep_gender", True)
    out = []
    for i, t in enumerate(tokens):
        key = t.lower()
        fake = ctx.vault.parts.get(key)
        if fake is None:
            is_first = (len(tokens) == 1 and key.split("-")[0] in pools()["name_gender"]) or (
                len(tokens) > 1 and i < len(tokens) - 1
            )
            if is_first:
                g = _gender(t) if keep_gender else "any"
                pool = names["f"] + names["m"] + names["n"] if g == "any" else names[g]
                fake = pick(ctx, f"first.{g}", pool)
            else:
                fake = pick(ctx, "last", pools()["last_names"])
            ctx.vault.add_part(t, fake)
        out.append(styled(fake, t))
    return " ".join(out)


def org(ctx: Ctx, real: str) -> str:
    fake = pick(ctx, "org", pools()["orgs"])
    m = ORG_SUFFIX.search(real)
    return f"{fake} {m[1]}{m[2]}" if m else fake


def location(ctx: Ctx, real: str) -> str:
    return pick(ctx, "city", pools()["cities"])


def address(ctx: Ctx, real: str) -> str:
    m = ADDRESS_PARTS.match(real)
    street = pick(ctx, "street", pools()["streets"])
    if not m:
        return f"{1 + ctx.vault.drbg.below('addr.num', 999)} {street} St"
    width = len(m[1])
    low = 10 ** (width - 1) if width > 1 else 1
    number = low + ctx.vault.drbg.below("addr.num", 10 ** width - low)
    letter = chars(ctx, "addr.num", UPPER, 1) if m[2] else ""
    return f"{number}{letter} {street} {m[4]}{m[5]}{shape(ctx, m[6], 'addr.unit')}"


# Contact details

def domain(ctx: Ctx, host: str) -> str:
    """Map a host to a fake one. The registrable part maps consistently; generic subdomains stay."""
    host = host.lower().rstrip(".")
    reg = registrable(host)
    fake_reg = ctx.vault.domains.get(reg)
    if fake_reg is None:
        fake_reg = pick(ctx, "domain", pools()["domain_words"]) + ".example"
        ctx.vault.domains[reg] = fake_reg
        ctx.vault.used.add(fake_reg)
        ctx.vault.touch()
    sub = host[: -len(reg)].rstrip(".")
    if not sub:
        return fake_reg
    labels = [lab if lab in GENERIC_SUBDOMAINS else shape(ctx, lab, "subdomain") for lab in sub.split(".")]
    return ".".join(labels) + "." + fake_reg


def email(ctx: Ctx, real: str, on_person=None) -> str:
    local, _, host = real.rpartition("@")
    runs = re.findall(r"[A-Za-z]+|[0-9]+|[^A-Za-z0-9]", local)
    alpha = [r for r in runs if r[0].isalpha()]
    known_first = pools()["name_gender"]
    if len(alpha) >= 2 and alpha[0].lower() in known_first and all(len(a) >= 2 for a in alpha):
        # first.last style: the local part is a name, so give it the same fake name as the person
        full = " ".join(a.capitalize() for a in alpha)
        if on_person is not None:
            on_person(full)
        else:
            person(Ctx(ctx.vault, ctx.text, {}), full)
    out = []
    for r in runs:
        if r[0].isalpha():
            key = r.lower()
            if key in ctx.vault.parts:
                out.append(styled(ctx.vault.parts[key], r))
            elif key in GENERIC_MAILBOXES:
                out.append(r)
            elif len(r) == 1:
                out.append(styled(chars(ctx, "letter", LOWER, 1), r))
            else:
                out.append(styled(pick(ctx, "mailbox", pools()["last_names"]).lower(), r))
        elif r[0].isdigit():
            out.append(chars(ctx, "digits", DIGITS, len(r)))
        else:
            out.append(r)
    fake = "".join(out) + "@" + domain(ctx, host)
    for _ in range(100):
        if ctx.free(fake):
            return fake
        fake = "".join(out) + chars(ctx, "digits", DIGITS, 1) + "@" + domain(ctx, host)
    raise RuntimeError("could not make a free fake email address")


def phone(ctx: Ctx, real: str) -> str:
    d = digits_of(real)
    if len(d) == 10 or (len(d) == 11 and d[0] == "1"):
        area = d[-10:-7] if ctx.options.get("keep_region") else None
        for _ in range(500):
            a = area or AREA_CODES[ctx.vault.drbg.below("phone.area", len(AREA_CODES))]
            line = a + "55501" + chars(ctx, "phone.line", DIGITS, 2)  # 555-0100..0199 is set aside for fiction
            new = ("1" if len(d) == 11 else "") + line
            candidate = fill_template(real, new)
            if ctx.free(candidate) and new not in ctx.vault.used:
                ctx.vault.used.add(new)
                return candidate
        raise RuntimeError("ran out of fictional phone numbers")
    uk = (d.startswith("44") and len(d) == 12) or (d.startswith("07") and len(d) == 11)
    for _ in range(500):
        if uk:
            # UK: Ofcom keeps 07700 900000-900999 (mobile) and 020 7946 0000-0999 (London) for drama
            national = d[2:] if d.startswith("44") else d[1:]
            body = ("7700900" if national.startswith("7") else "2079460") + chars(ctx, "phone.line", DIGITS, 3)
            new = ("44" if d.startswith("44") else "0") + body
        else:
            # elsewhere there is no reserved range we can rely on; keep the country code, randomise the rest
            keep = 2 if real.lstrip().startswith("+") else 0
            new = d[:keep] + chars(ctx, "phone.line", DIGITS, len(d) - keep)
        candidate = fill_template(real, new)
        if new != d and ctx.free(candidate) and new not in ctx.vault.used:
            ctx.vault.used.add(new)
            return candidate
    raise RuntimeError("ran out of fake phone numbers")


def url(ctx: Ctx, real: str) -> str:
    m = URL_PARTS.match(real)
    if not m:
        return shape(ctx, real)
    rest_tokens = re.findall(r"[A-Za-z0-9]+|[^A-Za-z0-9]", m[4])
    out, after_equals = [], False
    for tok in rest_tokens:
        if tok[0].isalnum() and (after_equals or len(tok) >= 12 or any(c.isdigit() for c in tok)
                                 or tok.lower() in ctx.vault.parts):
            out.append(shape(ctx, tok, "url"))
        else:
            out.append(tok)
        after_equals = tok == "="
    return m[1] + domain(ctx, m[2]) + (m[3] or "") + "".join(out)


def ip_address(ctx: Ctx, real: str) -> str:
    for _ in range(2000):
        i = ctx.vault.drbg.below("ip", 3 * 254)
        candidate = TEST_NETS[i // 254] + str(i % 254 + 1)
        if ctx.free(candidate):
            return candidate
    raise RuntimeError("ran out of documentation IP addresses")


# Money and secrets

def card(ctx: Ctx, real: str) -> str:
    d = digits_of(real)
    pool = [c for c in pools()["test_cards"] if len(c) == len(d) and c != d and c not in ctx.vault.used]
    if pool:
        new = pool[ctx.vault.drbg.below("card", len(pool))]
    else:
        # 0000... is not a real issuer prefix, so this can never charge anyone
        body = "0000" + chars(ctx, "card", DIGITS, len(d) - 5)
        new = body + checks.luhn_digit(body)
    ctx.vault.used.add(new)
    return fill_template(real, new)


def iban(ctx: Ctx, real: str) -> str:
    s = "".join(real.split()).upper()
    while True:
        bban = "".join(chars(ctx, "iban", UPPER, 1) if c.isalpha() else chars(ctx, "iban", DIGITS, 1) for c in s[4:])
        check = 98 - checks.iban_numeric(s[:2] + "00" + bban) % 97
        new = f"{s[:2]}{check:02d}{bban}"
        if new != s:
            break
    if " " in real:
        return " ".join(new[i:i + 4] for i in range(0, len(new), 4))
    return new


def routing(ctx: Ctx, real: str) -> str:
    while True:
        body = "0000" + chars(ctx, "routing", DIGITS, 4)
        new = body + next(d for d in DIGITS if checks.aba_sum(body + d) % 10 == 0)
        if new != digits_of(real):
            return fill_template(real, new)


def ssn(ctx: Ctx, real: str) -> str:
    d = digits_of(real)
    free = [x for x in (a.replace("-", "") for a in pools()["advertising_ssns"])
            if x not in ctx.vault.used and x != d]
    if free:
        new = free[ctx.vault.drbg.below("ssn", len(free))]
    else:
        new = "000" + chars(ctx, "ssn", DIGITS, 6)  # area 000 is never issued
    ctx.vault.used.add(new)
    return fill_template(real, new)


def api_key(ctx: Ctx, real: str) -> str:
    if real.startswith("-----BEGIN"):
        return "\n".join(line if line.startswith("-----") else shape(ctx, line, "key") for line in real.split("\n"))
    if real.startswith("eyJ") and real.count(".") == 2:
        return ".".join(p[:3] + shape(ctx, p[3:], "key") if p.startswith("eyJ") else shape(ctx, p, "key")
                        for p in real.split("."))
    for prefix in KEY_PREFIXES:
        if real.startswith(prefix):
            return prefix + shape(ctx, real[len(prefix):], "key")
    return shape(ctx, real, "key")


def secret_shape(ctx: Ctx, real: str, label: str) -> str:
    for _ in range(100):
        fake = shape(ctx, real, label)
        if fake != real:
            return fake
    raise RuntimeError("could not make a different value")


MAKERS = {
    "PERSON": person,
    "ORG": org,
    "LOCATION": location,
    "ADDRESS": address,
    "EMAIL": email,
    "PHONE": phone,
    "URL": url,
    "IP_ADDRESS": ip_address,
    "CARD": card,
    "IBAN": iban,
    "ROUTING": routing,
    "SSN": ssn,
    "API_KEY": api_key,
}


def make(type_: str, ctx: Ctx, real: str) -> str:
    """A fake for any type except DATE and MONEY, which the session handles (they shift or scale)."""
    maker = MAKERS.get(type_)
    if maker is not None:
        return maker(ctx, real)
    return secret_shape(ctx, real, type_.lower())
