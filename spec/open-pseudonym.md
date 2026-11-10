# Open Pseudonym v0.2

Status: draft 0.2, November 2026. Licence: CC BY 4.0. Wire version string: `"opn": "0.1"` (unchanged: policies,
vault files and receipts written under 0.1 still read the same).

Open Pseudonym is a way to keep personal data away from an AI model while the model still does the task well. Before
text reaches the model, personal values are replaced with stand-ins chosen for the task at hand. When the model
answers, the stand-ins are turned back into real values on the person's side. Secrets the model only needs to move
(a one-time code, a card number) become handles that are filled in outside the model, and only where they belong.
Every request that leaves can carry a signed receipt saying what was in it.

This document says what a conforming implementation does, closely enough that two implementations given the same
seed produce the same bytes. The test vectors in `vectors/` are the final word where this text is unclear.

## 1. What this is, and what it is not

It is **pseudonymisation** in the sense of GDPR Article 4(5): the data can no longer be tied to a person without
additional information (the vault), which is kept separately and protected. It is **not anonymisation**. Text that
went through it is still personal data for whoever holds the vault, and a determined reader can sometimes work out who
a text is about from what is left (the topic, a rare job title, a writing style). Implementations and the people who
ship them must not describe the output as anonymous, de-identified, or compliant with any law. Section 13 lists
wording that is accurate.

What it does promise, and what the receipts let anyone check:

1. Values the detectors found are replaced before the request leaves, according to a policy chosen by code.
2. The vault, the only link back to real values, does not leave the pseudonymisation domain (section 2).
3. No value the vault knows about is present in a request that carries a valid receipt (section 11).
4. A handle is filled in only into a place its binding allows (section 10).

## 2. Terms

- **Real value**: a piece of personal data as it appears in the input ("Dana Reyes", "482913").
- **Stand-in**: what the model sees instead. One of: a fake (realistic value of the same type), a tag (`[PERSON_1]`),
  a token (`person_9f3a0c12`), a format-preserving ciphertext, a generalisation ("someone"), a removal marker
  (`[EMAIL removed]`) or a handle (`{{OTP_1}}`).
- **Vault**: the table of real values and their stand-ins, plus the random seed and counters (section 8).
- **Session**: one policy plus one vault. Typically one conversation, task or dataset.
- **Pseudonymisation domain** (EDPB Guidelines 01/2025): the set of parties that may hold the vault. In this
  standard it is the person's device or the app operator's own systems. The model provider is outside it.
- **Source**: where input text came from, as established by the app (a verified email sender, a page URL).
- **Sink**: where a value is about to go (a tool name, the site a browser is on), as established by the app.
- **Egress**: the exact bytes sent to the model provider.

The app, not the model, supplies policies, sources and sinks. Nothing the model writes may change them.

## 3. Data types

| Type | Examples | Compared by |
|---|---|---|
| `PERSON` | Dana Reyes | whitespace-collapsed, lower case |
| `ORG` | Acme Corp | same |
| `LOCATION` | Lisbon; Boise, Idaho; Smalltown, MT | same |
| `ADDRESS` | 221 Baker Street, Apt 4 | same |
| `EMAIL` | dana@example.org | lower case |
| `PHONE` | (617) 555-0142 | digits only |
| `URL` | https://example.org/a | lower case |
| `IP_ADDRESS` | 192.0.2.10 | as written |
| `DATE` | 2026-03-12, March 12, 3/12/2026 | the calendar day it names |
| `MONEY` | $1,234.50, 40 EUR | as written |
| `CARD` | 4242 4242 4242 4242 | digits only |
| `IBAN` | GB82 WEST 1234 5698 7654 32 | no spaces, upper case |
| `ROUTING` | ABA routing number | digits only |
| `BANK_ACCOUNT` | account number | digits only |
| `SSN` | 123-45-6789 | digits only |
| `API_KEY` | keys, tokens, private keys | as written |
| `PASSWORD` | the value after "password:" | as written |
| `OTP` | one-time codes | digits only |
| `ID` | order #A12345, MRN 448812, CUST-00921 | as written |
| `USERNAME` | @dana_r | lower case |

Apps may add types. A type name matches `^[A-Z][A-Z0-9_]{1,31}$`. Unknown types follow the policy's default rule.

"Secret types" are `CARD IBAN ROUTING BANK_ACCOUNT SSN API_KEY PASSWORD OTP`. "Digit types" are
`CARD PHONE SSN ROUTING BANK_ACCOUNT OTP`.

## 4. Detection

An implementation runs three kinds of detector over the input and merges their spans.

**4.1 Shared patterns.** `data/patterns.json` lists regular expressions written in the subset that Python `re` and
JavaScript `RegExp` (with the `u` flag) agree on. For each pattern, every non-overlapping match is found from left to
right. The value is capture group `group`. If the pattern names a `check`, the value is kept only if the check passes:

- `card`: 13 to 19 digits, Luhn-valid, not all one digit, first digit 3 to 6, or 2 with the first four in 2221..2720.
- `iban`: country length from the ISO 13616 table in the reference SDKs, and mod-97 equals 1.
- `aba`: nine digits, first two in 00..12, 21..32, 61..72 or 80, and `3(d1+d4+d7) + 7(d2+d5+d8) + (d3+d6+d9)` is a
  multiple of 10.
- `ssn`: nine digits, area not 000, 666 or 9xx, group not 00, serial not 0000.
- `phone`: 10 to 15 digits.
- `date`: parses as a real calendar day (section 7.3).
- `name`: every space-separated token is at least two characters and not in `name_stopwords` (case-insensitive).

Some patterns are built by `tools/make_patterns.py` from word lists in `data/pools.json`: given names (`name_gender`
without `ambiguous_names`, such as "Will" or "May", which still need a cue), family names written first
(`family_first`, `family_first_words`, `middle_names`), places (`places`; those in `ambiguous_places`, such as
"Austin", count only after a place cue like "in" or "moved to"), organisations named after people (`org_names`) and
words such as Hospital or Bank. The lists are data, so every implementation reads the same ones.

**4.2 Known values.** Every real value held by the vault is matched again in new text, so a value that was hidden once
stays hidden even without the cue that found it. Apps may also pass lists (their contacts, their own company). Matching
modes: emails and URLs in any case; names, organisations, places and addresses of two or more words in any case
("dana reyes" is still Dana Reyes); single words as written or in all capitals (so the name Iris does not catch the
word iris); digit types with six or more digits by the same digits with up to two of the characters ` .()+-` between
each pair, optionally starting with `(` or `+`; shorter digit values (a 4-digit code) exactly as written. For a
person the app lists with two or more words, each word is also a known value, so "Dana called" is caught once the
app says Dana Reyes is a contact. Name parts (each token of a faked person,
except stopwords, `ambiguous_names` and one-letter tokens) are known values of type `PERSON`. A one-word `PERSON` or
`LOCATION` value that is in `ambiguous_names` or `ambiguous_places` ("Will", "Oxford") is never a known value: it is
hidden only where a cue finds it, and its plain uses elsewhere ("Will you join?") are neither masked nor leaks. Dates and amounts are not matched this way;
the patterns find them. Known values have priority 100.

**4.3 Other detectors.** Any detector that returns spans (an ML model, a domain rule set) may be added. Its spans carry
their own priority; the reference adapters use 30.

**4.4 Merging.** Before sorting, a `PERSON` span takes the highest priority of any shorter `PERSON` span inside it,
and of any `LOCATION` span that starts after it and ends where it ends plus one ("Isla Fairbanks" beats the city).
Sort all spans by priority (high first), then length (long first), then start (early first), then type name. Walk
the list and keep a span unless it overlaps one already kept. A `PERSON` span that lost to a span of another type
keeps each run of whole words the winner did not cover, if the run passes the `name` check; merge once more with
those runs added. Then known `PERSON` spans grow (4.5). Then:

- drop spans whose text equals (case-insensitive) a value on the session's allow list or the policy's `allow` list;
- only if the app declares that its input may already contain stand-ins (`masked_input`), drop spans whose text
  equals (case-insensitive) a stand-in this vault issued, which makes masking idempotent. By default input is
  treated as real: a real name that happens to equal an earlier fake is masked like any other value (otherwise it
  would reach the model as is, and restore would turn it into the wrong person).

**4.5 Growing known names.** A known `PERSON` value ("Reyes") may sit next to a part not seen yet ("Dana Reyes",
"D. Reyes"). On the left, when exactly one space comes before the span, take the word before it (back to a space,
tab, line break, `(`, `"` or `'`, never into the previous kept span). It joins the name if it is not a stopword and
not a key of `places`, and it is either an initial (`[A-Z].`) or a capitalised word of two or more letters that is a
given name in `name_gender` or does not start a sentence (the text before it, without trailing spaces and tabs, is
empty or ends in `. ! ? : " (` or a line break). On the right, a one-word span takes the next word when exactly one
space separates them and that word (up to a break or one of `. , ; : ! ? )`, never into the next kept span) is a
capitalised word of two or more letters, not a stopword and not a key of `places`.

## 5. Policies

A policy is a JSON object (schema: `schemas/policy.schema.json`):

```json
{
  "opn": "0.1", "type": "policy", "id": "draft_reply",
  "description": "Reply to a message...",
  "rules": {"PERSON": {"action": "fake", "keep_gender": true}, "OTP": {"action": "handle", "uses": 1, "ttl_s": 600}},
  "default": {"action": "tag"},
  "allow": []
}
```

Actions and their strength (how much they hide):

| Action | Strength | Restorable | Stand-in |
|---|---|---|---|
| `keep` | 0 | (nothing replaced) | the real value |
| `shift` | 1 | yes | the date moved by the session offset (dates only) |
| `generalize` | 1 | no | a coarser description ("someone", "March 2026") |
| `fake` | 2 | yes | a realistic value of the same type (section 7) |
| `tag` | 2 | yes | `[TYPE_n]` |
| `token` | 2 | yes | `type_` plus 8 hex digits of a keyed hash |
| `fpe` | 2 | yes | FF1 ciphertext of the digits (digit types only) |
| `handle` | 3 | only by `resolve` | `{{TYPE_n}}` |
| `drop` | 4 | no | `[TYPE removed]` |
| `refuse` | 5 | no | the whole request is refused |

Options: `fake` takes `keep_gender` (default true) and `keep_region` (default false, phones only). `handle` takes `uses`
(integer, default unlimited), `ttl_s` (seconds), `ask` (boolean), `tools` (list of tool names) and `sites` (list of hosts; an
entry `*.example.com` also allows every subdomain of example.com; a wildcard over a public suffix such as `*.com` or
`*.github.io` is an error). Any other option is an error. The starter profiles
set `ask` for CARD, IBAN, ROUTING and BANK_ACCOUNT, so moving money details always needs the person's yes.

Fallbacks: `fake` on a date means `shift`. `shift` on anything but a date means `fake`. A date that does not parse
under `shift` gets `tag`. `fpe` on a non-digit type, or on fewer than 6 digits, means `fake`.

**Only tighter.** An implementation must let code combine policies only in the stricter direction:
`tighten(a, b)` takes, per type, the rule with the higher strength (ties between different actions keep `a`), and
keeps only values both allow. When both rules are `handle`, their limits combine: the lower `uses`, the shorter
`ttl_s`, `ask` if either asks, and the intersection of `sites` and of `tools` (if both sides list sites, or both
list tools, and nothing is common, the result is `drop`). Applying overrides must fail if any override has a lower
strength than the rule it replaces, and an override with the same action keeps the old rule's limits the same way. There is no operation
that takes a policy from model output.

**Choosing a policy.** The app chooses. An implementation may offer a suggestion from the tool names an agent has
(the reference `suggest_profile`), but the result is advice to the app, never something the model picks.

Starter profiles ship in `data/profiles/`: `draft_reply`, `schedule`, `summarize`, `web_research`, `money_math`,
`browse_and_fill`, `logs`, `training_data`, and three levels for products that want a simple switch the person
controls: level 1 "Secrets" (`secrets_only`), level 2 "Contacts" (`contacts`) and level 3 "Everything" (`strict`).
Every level hides secret types as handles; higher levels add contact details, then names, organisations and places.

## 6. Masking

For one input text:

1. Detect and merge spans (section 4).
2. Work out stand-ins in this order: all `PERSON` spans by start position, then every other span by start position.
   People go first so that an email address like `dana.reyes@...` can reuse the fake name chosen for "Dana Reyes".
3. For each span: look up the rule for its type. The span is **kept** (left as written) when the rule is `keep`;
   when it is a date that parses, under `shift` or `fake`, and one of `holidays` is named in the 30 characters before
   it or the 20 after it (the holiday already gives the day away); or when it is a place under `generalize` whose
   kind in `places` is country, state, region or place (already general). `refuse` stops with an error naming the
   type.
   Otherwise compute the comparison key (section 3; dates use the ISO day) and look for an existing vault entry with
   the same type, key and action.
   - **Existing entry**: if this exact text was seen before, use the stand-in it got. Otherwise make the stand-in in
     the new shape (a shifted date rendered in this format, a fake name in this capitalisation, the fake digits in
     this layout, a scaled amount in this format) and record the new surface pair on the entry.
   - **New entry**: make the stand-in (section 7), add the entry.
4. Replace the spans, left to right.
5. For every handle in the result, produce a note (section 10.3).

JSON values (tool results) are masked string by string; keys are left alone. A string under the key `arguments` that
holds JSON is parsed, masked as JSON, and serialised compactly (no spaces, non-ASCII kept as is). Numbers with a
fraction or beyond 2^53 may be written differently by different JSON libraries; vectors avoid them. Chat messages (OpenAI or Anthropic shape) are masked
the same way, leaving alone only values the protocol needs exactly as written: the keys `role`, `type`, `id`,
`tool_call_id`, `tool_use_id`, `call_id`, `media_type`, `mime_type`, `mimeType`, `cache_control`, `toolCallId`,
`toolName` and `mediaType` at any depth; `model` only at the top of a request body; inside a block whose `type` is
`thinking`, `redacted_thinking` or `reasoning`, its `thinking`, `signature`, `encrypted_content` and (redacted) `data`,
which are signed by the provider and hold only stand-ins because the model never saw real values; and real binary
base64 (a `data` string in an object whose `type` is `base64`, or a `data:` URL with `;base64,`, but only if what
follows really is base64). Base64 whose media type is text (`text/*`, JSON, XML, CSV, YAML) is decoded, masked and
encoded again. Everything else is content, including `name`, `detail`,
metadata and documents. Values left alone are still read by the egress check (section 11.1), so personal data placed
under one of these keys stops the request rather than slipping out. When masking a JSON value that is data (a tool
result), its keys are masked too. Notes for handles are appended to the message that
mentions them: to a string `content` after a blank line, or as a final `{"type": "text"}` part, one line per note
starting `Note: `. A note already present in the message is not added again.

## 7. Making stand-ins

### 7.1 Randomness

Each vault has a seed of at least 16 bytes (32 recommended, from a cryptographic source). All choices come from:

```
block(label) = HMAC-SHA256(seed, utf8(label) || 0x00 || uint64_be(counter[label]));  counter[label] += 1
below(label, n): repeat { x = uint64_be(first 8 bytes of block(label)) } until x < floor(2^64 / n) * n; return x mod n
derive(purpose) = HMAC-SHA256(seed, "opn-derive" || 0x00 || utf8(purpose))
```

Counters are per label and are saved with the vault. The labels used below are part of the format.

A candidate fake is **free** if its lower-case form is not a stand-in already issued, not a real value or real name
part already seen, and does not occur (case-insensitive, as a whole word) in the text being masked.

`pick(label, pool)`: up to `3 * len(pool)` times, take `pool[below(label, len(pool))]` and return it if free. If none
was free, up to 200 times, take two such draws `a`, `b` and return `a-b` if free. Otherwise fail.

`chars(label, alphabet, n)`: n draws of `alphabet[below(label, len(alphabet))]`.

`shape(value, label)`: each A-Z becomes `chars(label, A-Z, 1)`, each a-z `chars(label, a-z, 1)`, each 0-9
`chars(label, 0-9, 1)`; anything else stays.

`fill(template, digits)`: if the template has the same number of digits, put the new digits in place of the old ones
and keep every other character; otherwise return the digits alone.

### 7.2 Fakes by type

Pools are in `data/pools.json`.

- **PERSON.** Split on spaces. A token in the particle list (`de del della da das dos du di van von der den ter ten
  bin ibn al el la le zu`) stays as written. For each other token, if its lower case is already a known name part,
  reuse that part's fake. An initial (`[A-Z].`) not yet known becomes `chars("initial", A-Z, 1) + "."`.
  Otherwise it is a first name if (one token and its first hyphen-piece is in `name_gender`) or (several tokens and it
  is not the last), else a last name. First names: gender `g` = `name_gender[first piece]` or `n`; with
  `keep_gender: false`, `g = any`; pick from `first_names[g]` (for `any`, the f, m and n lists concatenated) with label
  `first.<g>`. Last names: pick from `last_names` with label `last`. Record the part pair. Copy capitalisation: an
  all-capitals token of two or more letters gives an all-capitals fake, an all-lower token a lower-case fake.
- **ORG.** The core is the value without its legal suffix (`Inc LLC Ltd Corp Corporation GmbH PLC LLP Co`,
  optional dot). If an earlier `fake` ORG entry has the same core (case-insensitive) and a `core` in its metadata,
  reuse that core. Otherwise pick from `orgs` (label `org`); when the real value has a suffix, drop trailing
  describing words (`Labs Systems Works Partners Health Analytics Logistics Media Robotics Foods Legal Learning
  Capital Design Co Energy Retail Insurance Biotech Builders Travel Bank Studio Software Freight Clinic Advisors
  Furniture Games`) while more than one word is left. The stand-in is the core, plus the real suffix if there is one;
  the entry keeps the core as `meta.core`. When the real value had a suffix and its bare core is at least three
  characters and not a stopword, the pair (fake core, real core) is added as a surface of the entry, so "Acme" alone
  is a known value from then on and gets the same fake name.
- **LOCATION.** For `<town>, <state>` (a code in `us_state_codes`, or a state in `places`): pick from `cities` (label
  `city`) and keep `, <state>` as written. For a country, state or region in `places`: pick from the other places of
  the same kind and the same region, sorted by code point (label `place.<kind>`). Otherwise pick from `cities`
  (label `city`).
- **ADDRESS.** Postcodes first, from ranges no address uses, all with label `postcode`, up to 200 tries for a free
  value: a UK postcode becomes `ZZ99 ` plus one digit and two letters from `ABDEFGHJLNPQRSTUWXYZ`; a US ZIP becomes
  `000` plus two digits (and `-` plus four digits if it had them); a Canadian code becomes `Z`, a digit, a letter, a
  space if the real one had it, a digit, a letter and a digit, letters from `ABCEGHJKLMNPRSTVWXYZ`. Street addresses:
  parse `number[letter] name suffix[.]rest`. Number: same digit count, from `below("addr.num", ...)`;
  letter from `chars("addr.num", A-Z, 1)` if present; name: pick from `streets` (label `street`); suffix kept as
  written; rest (unit) through `shape(rest, "addr.unit")`. If the address does not parse: `<1 + below("addr.num", 999)>
  <street> St`.
- **Domains** (used by EMAIL and URL). Lower-case the host, take its registrable domain (last two labels, or three if
  the last two are a public suffix, using the longest match in `public_suffixes` from the pools, a subset of the
  Public Suffix List that includes shared hosting such as `github.io`). If the vault has no fake for it, pick from `domain_words` (label
  `domain`) and append `.example` (reserved by RFC 2606). Subdomain labels in the generic list stay, others go through
  `shape(label, "subdomain")`.
- **EMAIL.** Split the local part into runs of letters, runs of digits and single other characters. If there are at
  least two letter runs, all of at least two letters, and the first is in `name_gender`, the local part names a
  person: title-case the letter runs, join them with spaces, and register that person (a PERSON entry if the PERSON
  rule is `fake`, nothing if it is `keep`, otherwise just the name parts). Then each letter run becomes its part fake if known, stays if it is a
  generic mailbox word, becomes `chars("letter", a-z, 1)` if it is one letter, else a pick from `last_names` (label
  `mailbox`) in lower case; capitalisation copied. Digit runs become `chars("digits", 0-9, len)`. The domain is
  faked as above. While the result is not free, try again with one digit from `chars("digits", 0-9, 1)` appended to
the local part (a fresh digit each try).
- **PHONE.** North American numbers (10 digits, or 11 starting with 1): area code kept with `keep_region`, else
  `AREA_CODES[below("phone.area", 10)]`; the line becomes `555` `01` plus `chars("phone.line", 0-9, 2)` (555-0100 to
  555-0199 is set aside for fiction). Try up to 500 times for a free number. UK numbers (+44, 12 digits, or 07..., 11
  digits) use Ofcom's drama ranges: mobile `7700900` and London `2079460`, plus `chars("phone.line", 0-9, 3)`.
  Anything else: keep the first two digits if the number starts with `+`, the rest from `chars("phone.line", ...)`.
  The result is laid out with `fill` over the original.
- **USERNAME.** Drop the `@`, split the rest like an email local part and fake each run the same way; up to 100
  tries for a free `@` value that differs from the real one in lower case.
- **URL.** Scheme and port stay; the host is faked as a domain; in the rest, every alphanumeric run that follows `=`,
  is 12 or more characters long, contains a digit, or contains a known real name part of three or more letters
  (so `/in/danareyes` is caught) goes through `shape(run, "url")`. So does every path run (before `?` or `#`) on a
  host whose registrable domain is in `profile_hosts`, unless it is in `profile_path_words`, and every run in a path
  segment that holds a word of three or more letters found in `name_gender`.
- **IP_ADDRESS.** `i = below("ip", 762)` until free; `TEST_NETS[i // 254] + (i % 254 + 1)` with the RFC 5737 blocks
  `192.0.2.`, `198.51.100.`, `203.0.113.`.
- **CARD.** From `test_cards` with the same length and not yet used, pick `below("card", count)`. If none is left:
  `"0000" + chars("card", 0-9, len - 5)` plus the Luhn digit. Laid out with `fill`.
- **IBAN.** Same country; each letter of the account part from `chars("iban", A-Z, 1)`, each digit from
  `chars("iban", 0-9, 1)`; check digits recomputed. Grouped by four if the real value had spaces.
- **ROUTING.** `"0000" + chars("routing", 0-9, 4)` plus the digit that satisfies the ABA sum.
- **SSN.** From `advertising_ssns` not yet used, pick `below("ssn", count)`; if none is left, `"000" +
  chars("ssn", 0-9, 6)`. Laid out with `fill`.
- **API_KEY.** PEM blocks: lines starting `-----` stay, others go through `shape(line, "key")`. JWTs: each part
  through `shape`, keeping a leading `eyJ`. Otherwise keep the longest known prefix and `shape` the rest.
- **Anything else** (PASSWORD, OTP, BANK_ACCOUNT, ID, app types): `shape(real, lower(type))`, repeated until it differs
  from the real value.

### 7.3 Dates

Formats read and written: `YYYY-MM-DD`; `M/D/YYYY` (or `D/M/YYYY` when the session is day-first) with zero padding
kept per part; `Month D[st|nd|rd|th][, YYYY]`; `D[st|nd|rd|th] Month[ YYYY]`. Month names may be full, three letters
(optionally with a dot), or `Sept`. Without a year, the year is the current year of the session clock (UTC).

The vault's date offset is drawn once: `w = below("date.offset", 16) - 8; if w >= 0 then w += 1; offset = 7 * w`
days, so one to eight weeks either way. Whole weeks keep the weekday ("Thursday" in the text stays true) and the
season stays. A birth date (one of `birth_cues` in the 40 characters before it, and a year given) moves by `-offset`
instead when `day + offset` would give a different age than `day` on the session's current UTC day. `shift` renders `day + offset` in the
original format: a full month name stays full, a three-letter one stays three letters (`Sept` stays `Sept` only for
September), `May` counts as full, an ordinal suffix is recomputed, a missing year stays missing.

`generalize` gives `Month YYYY`, or `Month` without a year.

### 7.4 Amounts

`fake` scales an amount by the vault's money factor, drawn once as `2 + below("money.factor", 3)`, so whole cents
stay whole and sums stay consistent. Formats: a symbol `$ € £` then digits (optional thousands commas, optional two
decimals), or digits then `USD EUR GBP dollars euros`. Commas and decimals are kept as in the original.
`generalize` rounds to whole units, then to two significant figures above 99, and prefixes `about `.

### 7.5 Tags, tokens, format-preserving encryption, generalisation

- `tag`: `[TYPE_n]`; n counts per type within the vault, starting at 1, shared with handles.
- `token`: `lower(TYPE) + "_" + first 8 hex digits of HMAC-SHA256(token_key, TYPE + ":" + key)`. `token_key` is
  `derive("token")` unless the app pins one, which keeps tokens stable across sessions (useful for logs).
- `fpe`: NIST SP 800-38G FF1 with AES-256, radix 10, key `derive("fpe")` unless pinned, tweak = ASCII type name.
  CARD keeps the first and last four digits and cycle-walks the middle until the Luhn check passes. ROUTING and SSN
  cycle-walk the whole number until their checks pass. PHONE with 10 or 11 digits keeps all but the last seven.
  Others encrypt all digits. The layout is kept with `fill`. With the key alone, anyone can reverse it.
- `generalize`: PERSON "someone", ORG "an organization", ADDRESS "a street address", EMAIL "an email address",
  PHONE "a phone number", URL "a web link", IP_ADDRESS "an IP address", DATE and MONEY as above, anything else
  `[TYPE]`. LOCATION: `<town>, <state>` gives `a city in <state name>` when the town is in `places`, else
  `a town in <state name>`; a place in `places` gives `a <kind> in <where>`, or `a <kind>` when `where` is empty or
  the 40 characters after the value start with `, ` and `where` without a leading `the `; anything else `a place`.
  Postcodes give their area: the UK outward code, the first three ZIP digits plus `xx`, the first three characters
  of a Canadian code.
- `drop`: `[TYPE removed]`.

## 8. The vault

State: seed, counters, entries, issued stand-ins, real values seen, name parts both ways, domain map, per-type
numbers, date offset, money factor, optional pinned keys. Each entry has an id (`e1`, `e2`...), type, real value,
key, action, first stand-in, whether it is restorable, its surfaces (stand-in surface to real surface) and, for
handles, binding data.

At rest the vault is encrypted with AES-256-GCM, a fresh 12-byte nonce, and additional data `opn-vault-v1`:
`{"opn": "0.1", "type": "vault", "alg": "A256GCM", "nonce": b64url, "ciphertext": b64url}`. The key never sits next
to the file. The vault is personal data; protect it like the original text.

## 9. Restoring

Restoring finds, in one pass, four kinds of match and settles overlaps by earliest start, then longest:

1. **Exact.** Every surface stand-in of every restorable entry, as written or in all capitals (all capitals map to the
   real value in capitals); emails, URLs and tokens in any case. Name parts restore to the real part. Word edges are
   respected (`Maya's` restores, `Mayan` does not).
2. **Handles.** `{{TYPE_n}}` the vault issued. For display they become `[<description>]`; the real value appears only
   through `resolve` (section 10) or when the caller explicitly asks to reveal.
3. **Digits.** A run of 6 to 23 digits with light formatting whose digits equal a fake or FPE stand-in of a digit type
   restores to the real digits laid out as the model wrote them (also when the model dropped a leading 1).
4. **Dates.** A date the model wrote that names a shifted day restores to the real day in the model's format.

Tags and handles that look like ours but are not in the vault are reported, never guessed.

**Streaming.** Let `L` be the longest stand-in (at least 40). After each chunk, find matches in the buffer. Everything
up to `len(buffer) - (L + 1)` is final, except that the cut moves back to the start of any match that crosses it.
Emit the restored text before the cut and keep the rest, plus one character of left context for word-edge checks.
On the last chunk, restore and emit everything.

## 10. Secret handles

### 10.1 Creation

A span whose rule is `handle` becomes `{{TYPE_n}}` with binding data:

- `sites`: the rule's `sites`, or else the exact host of the source (the host of `source.site`, or the domain of
  `source.sender`), as WebOTP binds a code to one origin: a code mailed by acme.com fills on acme.com, not on
  docs.acme.com, where anyone might host a form. A bare public suffix (github.io) is no binding. The source is supplied
  by the app from facts it trusts (for email, a verified sender).
- `tools`: the rule's `tools`, if any.
- `uses_left`: the rule's `uses`, if any.
- `expires_at`: for OTP, `now + ttl`. Text is untrusted, so a phrase in it ("expires in 10 minutes", "valid for 1
  hour") may only shorten the rule's `ttl_s`, never lengthen it; with no `ttl_s`, a phrase alone counts for at most
  3600 seconds.
- `ask`: the rule's `ask`.
- `description`: what the model is told (10.3).

### 10.2 Filling

`resolve(args, sink)` restores a tool call's arguments right before the tool runs:

1. Collect every handle in every string of the arguments. An unknown handle is refused (`unknown handle`).
2. For each, refuse if it has neither `sites` nor `tools` (`not bound to a site or tool`: fail closed, so a secret
   read with no known source can never be sent anywhere), if expired (`expired`), out of uses (`already used`), the sink's tool is not in `tools` (`not
   allowed for this tool`), or `sites` is non-empty and the sink's host is not one of them (exactly, or under a `*.`
   entry) (`bound to a different site`). The sink's host is read the way a browser reads it: a backslash counts as a slash, and anything
   before an `@` in the authority is ignored. If `ask` is set, or this tool and site pair is new for the handle and the app registered an
   approval callback, ask the app; no callback with `ask` set is a refusal (`needs the person's approval`), a "no" is
   `not approved`.
3. Only if every handle passed: restore all strings, filling handles with real values. Then count one use per handle
   and remember the sink.

Strings that were not changed but contain an email, phone, card, IBAN, account number or URL are reported with origin
`model`: the model wrote that value itself, which an app may want to show the person before acting.

A browser filler (reference: `open_pseudonym.browser`) checks the sink against the URL of the frame that holds the
field, types the value, masks the field in screenshots, and checks afterwards that the value is not visible in the
page text.

### 10.3 Notes

The model is told, for each handle it sees:

```
{{OTP_1}} is a 6-digit one-time code from acme.com, valid until 14:32 UTC. Write {{OTP_1}} exactly where the value is needed; the real value is filled in outside the model.
```

Descriptions: OTP `a N-digit one-time code[ from SITE][, valid until HH:MM UTC]`; PASSWORD `a password[ for SITE]`;
CARD `a BRAND card ending NNNN` (Visa, Mastercard, American Express, Discover, else "payment"); IBAN `a bank account
(IBAN, CC) ending XXXX`; BANK_ACCOUNT `a bank account number ending NNNN`; ROUTING `a bank routing number`; SSN `a
social security number`; API_KEY `an API key`; anything else `a <type in lower case with spaces> value`.

These descriptions tell the model a card's brand and last four digits and an IBAN's country and last four
characters, which is what people expect to see and lets the model pick the right card. An app that wants to hide
even that can use `drop` or `fpe` instead of `handle` for those types.

## 11. Egress check and receipts

### 11.1 The check

Before a request is sent, run the check on its exact bytes. It reads the raw text and, if the bytes parse as JSON,
every key and string value (decoded), all joined by newlines, so neither escapes nor a bare JSON number can hide a
value.

1. Blank out (replace with spaces) every restore match (section 9).
2. Search what is left for every real value of every entry whose action is not `keep`, in the known-value modes of
   4.2 (digit types with six or more digits by digits, shorter ones as written; IBAN in any case with and without
   spaces), plus every real name part of three or more letters that is not in `name_stopwords`.
3. Then run detection (section 4) again over everything a person could have written: for JSON, every key and every
   string except the top-level `model`, signed reasoning and real binary base64; text sent as base64 is decoded and
   read. A proxy also checks the query string. Detection runs on this text with every restore match blanked out (so
   a slice of a long fake is not taken for a new name), and reads the context of each span from the text before
   blanking. Any span that masking would not keep (section 6, step 3) and that is not a stand-in is also a leak.
   This catches fields masking left alone.
4. Any hit is a leak. A conforming sender does not send a request with a leak; it reports the types, never the values.

This proves that no value **the vault knows**, and no value the detectors find in the outgoing bytes, left. It cannot
prove anything about values no detector recognises.

### 11.2 Receipts

A receipt is a compact JWS (RFC 7515) signed with Ed25519 (`alg: EdDSA`, RFC 8037). Protected header, canonical JSON
(RFC 8785), exactly `{"alg": "EdDSA", "kid": <thumbprint>, "typ": "opn-egress+jws"}`. `kid` is
`sha-256:` + base64url of SHA-256 over the canonical JWK `{"crv": "Ed25519", "kty": "OKP", "x": ...}` (RFC 7638).

Payload (canonical JSON, integers only):

```json
{"opn": "0.1", "type": "egress", "session": "...", "seq": 1, "iat": 1793836800, "prev": null,
 "dest": "api.example.com", "payload": "sha-256:...", "policy": "sha-256:...",
 "stand_ins": {"OTP": 1, "PERSON": 2}, "check": {"known_values": 7, "found": 0},
 "detectors": ["rules@1", "known@1"]}
```

`payload` is the digest of the exact bytes sent. `policy` is the digest of the canonical policy document. `prev` is
the digest of the previous receipt's token (ASCII bytes) in the same log, or `null` for the first. `stand_ins` counts
distinct vault entries whose stand-ins appear in the payload. `check.known_values` is the number of non-`keep`
entries at the time; `check.found` must be 0 for a request that was sent.

A log is a folder holding `receipts.jsonl` (one token per line) and, optionally, `payloads/NNNNNN.bin` (the exact
bytes; these hold stand-ins, not real values). Verifying a log checks each signature, that `seq` counts 1, 2, 3...,
the `prev` chain, `found` is 0, each stored payload's digest (when a `payloads` folder exists, a missing payload is a
problem, and so is a stored payload with no receipt), and, given the vault, the check again on each payload. A damaged
line or a missing `receipts.jsonl` is reported, never fatal, and so are an empty log and, when a vault is given, a
log with no payload left to re-check. Given the session id, every receipt must name it. A chain
cannot show that receipts were cut off the end; a verifier that kept the number of requests sent or the digest of the
last receipt (the proxy returns each receipt in a header) compares them to detect it.

## 12. Bindings

### 12.1 HTTP proxy

A local proxy speaks the provider's own API (OpenAI Chat Completions, OpenAI Responses, Anthropic Messages), so an
app only changes its base URL. It masks the whole request body, not only the messages: system prompts, documents,
message names, metadata and tool descriptions are content too; only the structural keys of section 6 and base64 data
stay as they are. It masks twice, so a name learned late in the body (in a message) is also caught where it appeared
earlier without a cue (in the system prompt). Then it runs the egress check, records a receipt, forwards to the
upstream, and restores responses, streamed or not. Streamed tool-call arguments are buffered until complete, then resolved. Request headers it reads (all
optional, set by the app, never forwarded upstream):

- `x-opn-session`: session id; requests with the same id share a vault.
- `x-opn-profile`: one of the proxy's configured profiles; the proxy refuses names it was not configured with, and the
  result is always tightened with the proxy's base policy.
- `x-opn-source-sender`, `x-opn-source-site`: the source for handles.

Response headers: `x-opn-receipt` (the receipt token) and `x-opn-unknown` (stand-ins the model invented).

### 12.2 MCP

An MCP middleware sits between an MCP host and a server. Results of `resources/read` and `prompts/get` are masked
like any text, and a resource address the host got from a masked listing is restored before the read goes to the
server. Every masked result goes through the egress check of section 11.1; a result that fails it is replaced by an
error ("Withheld: ..."). Tool results (`content` text, `structuredContent`) are
masked before they reach the host and its model; tool arguments are resolved (section 10.2) before they reach the
server, with the sink `{"tool": <tool name>, "site": <the site configured for that tool, if any>}`. Sites are set
per tool: a site for a whole server would let a handle bound to it be filled into any of its tools, including ones
that send messages. A refused handle
becomes a tool error whose text is the refusal reason. Handle notes are appended to the tool result as an extra text
item.

## 13. Wording

Accurate: "personal details are replaced with consistent stand-ins before anything leaves your device"; "the key to
undo it never leaves your device"; "pseudonymisation, a safeguard named in GDPR Articles 25 and 32"; "reduces what
the AI provider can learn about you"; "no value we detected was sent, and each request carries a receipt you can
check".

Not accurate, never use: "anonymous" or "anonymised"; "GDPR-compliant", "HIPAA-compliant" or "de-identified";
"not personal data"; "impossible to re-identify"; "zero-knowledge".

Notes for specific regimes: shifting dates does not meet HIPAA Safe Harbor, which keeps only the year; fakes here are
drawn at random rather than derived from the real value, in line with 45 CFR 164.514(c); CCPA's "deidentified"
needs public commitments and contracts, so the output is "pseudonymized" in CCPA terms too.

## 14. Security and privacy considerations

- **Re-identification from context.** Studies show language models can infer who a text is about from what remains
  (Staab et al., ICLR 2024; AgentDoxx, 2026). Use `generalize` or `drop` for details the task does not need, and
  measure with the benchmark in `bench/`.
- **Detector misses.** Patterns and small models miss things. Add the app's own known values (contacts, the person's
  own name), use an ML detector for names, and treat the egress check as proof for known values only.
- **Prompt injection.** Text the model reads may tell it to send a handle somewhere else. Bindings are checked by
  code against sinks the app sets; the model cannot widen them. A model that writes a real-looking email address of
  its own is flagged with origin `model`.
- **The vault is the crown jewel.** Encrypt it, keep it inside the pseudonymisation domain, give it an expiry that
  matches the task, and never log it.
- **Logs.** Never log real values. Receipts and stored payloads hold stand-ins only.
- **Caching.** Stand-ins are deterministic within a session, so repeated prefixes stay byte-identical and provider
  prompt caches keep working. System prompts without personal data can be left unmasked to keep cache hits.
- **Images and audio** are out of scope for v0.2. Text inside images reaches the model as is.

## 15. Conformance

| Level | Requires |
|---|---|
| L1 | Sections 3 to 9 with the shared patterns, the known-value detector, and the vault |
| L2 | L1 plus at least one name detector beyond the patterns (an ML model or the app's own lists) |
| L3 | L2 plus handles (section 10), streaming restore, and egress receipts (section 11) |

An implementation conforms at a level when it passes every vector in `vectors/` for the sections that level covers.
Vectors fix seeds and clocks so outputs are exact.
