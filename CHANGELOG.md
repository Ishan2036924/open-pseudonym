# Changelog

## 0.2.0 (2026-11-09)

A critic pass ran real sentences through the strictest level and found values that still reached the model. This
release closes those gaps and keeps more of the meaning the model needs.

### Found more

- Names without a cue: a list of about 1,150 given names from many cultures, so "I met Priya" and "Daniel Smith
  signed" are caught, along with family-name-first names ("Zhang Wei", "Nguyễn Văn An"), middle initials and
  particles ("de la", "van der"). Names that are everyday words ("Will", "May", "Grace") still need a cue, and are
  hidden only where a cue finds them, so "Hi Will" is hidden and "Will you join?" is not.
- A name is never half hidden. In 0.1.1, "Ms. Reyes ... Dana Reyes" went out as "Dana Yilmaz". A full name now wins
  over a part of it, a known surname pulls in the first name or initial next to it, and a name that loses to a place
  keeps its other words.
- Record numbers (new `ID` rules): customer, patient (MRN), passport, licence and tracking numbers after a cue;
  order, ticket, invoice and similar numbers after a cue with a marker ("order #A12345") or when they mix letters,
  digits and dashes, so "order 10000 units" stays a quantity; and prefixed codes such as `CUST-00921`. Standards and
  CVE ids are left alone.
- Places (`LOCATION`): about 700 countries, states, regions and large cities, "Smalltown, MT" style towns, and
  places that are also names ("Austin", "Jackson") only after a place cue such as "in" or "moved to".
- Postcodes: UK, Canadian, and US ZIP codes after a state or a zip cue.
- Usernames (new `USERNAME` type): `@handles` and Slack-style mentions. Common code annotations (`@property`,
  `@media`) and times ("@3pm") are not people.
- Organisations: hospitals, banks, universities and similar ("St. Mary's Hospital", "Bank of America", but not
  generic phrases such as "Data Center"), and
  companies named after people ("Morgan Stanley") are organisations, not people.
- Links: on profile sites (linkedin.com/in/..., github.com/...) every path word is hidden, and so is any path segment
  that holds a given name.
- Greetings in several languages ("Hola María", "Bonjour", "Namaste").

### Kept the meaning

- Dates move by 1 to 8 whole weeks (was up to 26), so the season stays. A date named next to a holiday ("Christmas
  Day, December 25") keeps its day, since the holiday already gives it away. A birth date moves the other way if the
  usual shift would change the person's age.
- "Acme Corp" and a later bare "Acme" share one fake name; a fake company never gets two suffixes.
- Countries and states become another country on the same continent or another state; summaries keep them as they
  are and describe cities as "a city in Idaho" (or just "a city" when the state follows).
- Postcodes are faked from ranges no address uses (UK ZZ99, US 000xx, Canadian Z..) and generalised to their area
  (NW1, 021xx, K1A).

### Fixed

- Level 2 (Contacts) flagged a kept first name as a leak when an email with that name was faked, so the proxy refused
  the request. Reported by an early adopter.
- The egress check reported values we chose to keep (a holiday date, a state in "a city in Texas") and slices of a
  long fake ("Rowan Whitlock" inside "Taylor Rowan Whitlock"). It now asks the same keep rule as masking and blanks
  our own stand-ins before looking for new values. On 400 random documents: 0 false alarms, and 340 of 340 planted
  real values still caught.

### Other changes

- `policy_for(profile, level)` (`policyFor` in TypeScript): the task's profile, made stricter by the person's level.
- Shared patterns are compiled once per process, and the known-value search is reused while its values are
  unchanged, so the larger rule set masks at the same speed as 0.1.1 (median 0.5 ms per item offline).
- The hand-written benchmark set gained `ID` labels for its three record numbers, which 0.1 had no type for.
- Data: `tools/make_lexicon.py` writes the word lists into `data/pools.json`; `tools/make_patterns.py` builds the
  shared regexes from them. 109 shared test vectors (was 88); both SDKs pass all of them.

## 0.1.1 (2026-11-06)

- Release check: first release through npm trusted publishing (staged, approved by a maintainer). No code changes.
- README: install badges and links to the published packages.

## 0.1.0 (2026-11-06)

- Specification v0.1: detection, task policies, stand-ins, the vault, restoring, secret handles, egress receipts,
  HTTP proxy and MCP bindings, conformance levels.
- Python SDK: core, local proxy (OpenAI Chat Completions, OpenAI Responses, Anthropic Messages, streaming), MCP
  middleware and gateway, Playwright handle filler, ML detector adapters (GLiNER, spaCy, Presidio), `opn` command.
- TypeScript SDK: core and Vercel AI SDK middleware.
- Shared test vectors, JSON schemas, offline benchmark.

### Fixed before the first release (two independent security reviews)

- Secret handles fail closed: a handle with no site or tool binding is never filled. Handles bind to the exact host
  of their source (a `*.example.com` policy entry opts in to subdomains); cards and bank details ask the person first.
- Tightening a policy keeps every handle limit (uses, ttl, ask, sites, tools). Text can only shorten a code's
  lifetime, never extend it; "expires in 0 minutes" is expired.
- The proxy masks the whole request body (documents, names, metadata, tool descriptions), twice, and leaves signed
  reasoning untouched. The egress check also re-runs detection over every string and key, so data in a field masking
  skipped stops the request. MCP masks resources and prompts and checks every result.
- Known names match in any case and across any whitespace; short codes are hidden again when history is re-sent; a
  real value that equals an earlier fake is masked; name slugs in links are hidden.
- `verify` reports missing payloads, payloads without receipts, missing logs and receipts from another session, never
  crashes on a bad line, and accepts an outside anchor (`--expect-count`, `--expect-last`) for cut-off tails.
- Shared hosting suffixes (github.io and others) are never a binding; URLs are read the way browsers read them.
- Fake-name pools no longer contain ordinary words; the email pattern is length-bounded (no slow inputs).
- Levels 1 to 3 (`load_level`, `LEVELS`) for products that offer people a simple switch.
