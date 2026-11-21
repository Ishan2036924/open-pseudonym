# Changelog

## 0.4.0 (2026-11-21)

A LiteLLM proxy guardrail, so any app behind a LiteLLM proxy gets Open Pseudonym from a few lines of `config.yaml`.
Also fixes from code scanning and property-based fuzzing in both SDKs. No change to the wire format or the vectors.

### Added

- **LiteLLM guardrail** (`open_pseudonym.litellm.OpenPseudonymGuardrail`, extra `[litellm]`, spec 12.3,
  `guides/litellm.md`): masks every model-bound field before the call and runs the egress check; checks the final
  request again after routing, just before each provider attempt, and signs one receipt per attempt naming the
  deployment's host; restores answers and streams (tool-call arguments buffered until complete) into copies, never
  into objects LiteLLM caches; fills handles only for `fill_tools`, with release records. Chat Completions, Responses,
  Anthropic Messages and embeddings are handled; other call types are refused unless listed in `skip_call_types`.
  Sessions are keyed by the caller's LiteLLM identity plus `x-opn-session`. Tested with LiteLLM 1.108.x, end to end
  through the real proxy against a fake model that records the bytes it received, with planted-defect tests for the
  egress check and the second check.

### Changed

- The HTTP-free half of the proxy (sessions, vault files, receipt logs, body masking and restoring) moved to
  `open_pseudonym.gateway.Gateway`; `Proxy` builds on it and behaves as before. Logs of sessions dropped from the
  session cache are now dropped too (they are reopened from disk when needed).
- **Tests and CI.** Property-based fuzzing in both SDKs (Hypothesis in the `[test]` extra, fast-check as a pinned dev
  dependency): detection, mask then restore, streaming restore cut anywhere, `resolve_args` with hostile arguments,
  sinks and approval answers, the egress check, sensitive references, `verify_log` on damaged logs, canonical JSON
  (idempotent, and byte-equal between Python and TypeScript on a seeded corpus), the gateway and the LiteLLM
  guardrail. Seeded; 60 examples per property in the normal suites, 1,000 in a new `fuzz` CI job,
  `OPN_FUZZ_EXAMPLES` for more. `ruff check` (E4, E7, E9, F) runs in CI and `tools/check_all.sh`.

### Fixed

- **Polynomial ReDoS (TypeScript, CodeQL `js/polynomial-redos`).** Trailing dots were trimmed with `/\.+$/` and
  whitespace with `/[ws]+$/`, which backtrack quadratically on a long run that is not at the end: a 50,000-character
  host took 3 to 7 s in `isPublicSuffix`, `boundSite` and `siteMatches`, and `stripWs` 5 s. They are loops now, with
  the same results as Python's `rstrip` and `strip` (which were already linear).
- **Quadratic `registrable` (both SDKs).** It tried every suffix length of a host: 50,000 dots took 12.5 s in Python
  and 15.8 s in TypeScript. It now tries no more labels than the longest known suffix has.
- **TypeScript canonical JSON accepted values that are not JSON.** An array with holes came out as `[1,,2]`, and a
  `Date`, `Map`, `Set`, typed array or boxed string as `{}` or index keys, so `resolveArgs` signed the digest of other
  arguments. They are refused now, as in Python, and such a call is refused with `malformed` (spec 10.4).
- **Gateway restore on answers of an unexpected shape.** A provider answer with a null or mistyped part (`"choices":
  [null]`, a number where a list belongs) raised `AttributeError` or `TypeError`: the local proxy answered 500 and the
  LiteLLM guardrail failed the call. Parts that are not the expected shape are now passed through unchanged.
- **LiteLLM guardrail header values that are not text** (an object in `x-opn-source-site`) raised `AttributeError`
  out of the pre-call hook instead of being ignored.

## 0.3.0 (2026-11-20)

Who allowed each secret to be filled in, and a way to show a log was not cut short. Spec v0.3. Everything 0.2 wrote
reads the same; the wire label stays `"opn": "0.1"`. A 0.2 verifier reading a log that holds release records reports
them as damaged lines.

### Added

- **Release records** (spec 10.4, `schemas/release-record.schema.json`, `typ` `opn-release+jws`): with a
  `release_log` on the Session (`releaseLog` in TypeScript), `resolve_args` signs one record per handle into the same
  log and chain as egress receipts: handle, data type, source, sink, a digest of the call with handles unfilled, who
  allowed it (`authority`: `binding`, `person`, `consent` or `policy`, with `by`, `channel`, `ref`, `digest` and
  `shown`, the digest of what the approver was shown), and the uses left. Refusals are recorded too, with their code.
  The record is written first: if the write fails nothing is filled, no use is counted, and `HandleRefused` carries
  `not_recorded`. No record holds a value or a hash of one.
- **Stable refusal codes** on `HandleRefused.code`: `unknown_handle`, `unbound`, `expired`, `used_up`, `wrong_tool`,
  `wrong_site`, `needs_approval`, `not_approved`, `not_recorded`. The text is unchanged.
- **Approvals that say who** (`Approval`): the approval callback still returns a bool, and may return an `Approval`
  with `by`, `channel`, `ref` and `digest`, so an app can pass an OAC Consent's id and token digest.
- **Checkpoints** (spec 11.3, `schemas/checkpoint.schema.json`, `typ` `opn-checkpoint+jws`): a head of the log signed
  by a key that is not the writer's (`make_checkpoint`, `EgressLog.checkpoint`, `opn checkpoint`).
  `verify_log(..., anchors=, anchor_key=)` (`opn verify --anchor --anchor-pub`) reports `proven_to`, `status`
  (`complete` or `prefix`) and `reason`, and problems for a checkpoint past the end of the log ("cut off after seq
  N"), a head that does not match, and a checkpoint signed by the writer's own key. `verify_log` also checks release
  records. `expect_count` and `expect_last` work as before.
- **Sensitive References stay opaque** (spec 10.5): `sref:<kind>:<id>` and `⟦sref:<kind>:<id>⟧` are never masked,
  never a stand-in, never restored or filled (a stream never cuts one in half), and never an egress leak or a value
  the model wrote. The spec says where Pseudonym handles end and Sensitive References begin, claims no
  interoperability, and offers a field table for the draft's open question on audit events.
- Spec 11.2 now says a chain proves order, not completeness; 12.2 notes how SEP-1913 trust annotations could point at
  a record (no claim of adoption); 14 says what a release record does not prove.
- Vectors: `releases.json`, `checkpoints.json`, a scenario and detect cases for references. Conformance 109 to 237.
- `opn mcp-gateway --log-dir`, and the proxy, write release records for the handles they fill.

### Fixed after review

- A value stuck to a sensitive reference is no longer hidden by it. The reference grammar is strict (a lower-case
  kind and a 26-character ULID, ending at a word boundary), and only a detected span lying fully inside a reference is
  exempt, in masking, in the egress detection pass and in the model-origin report. Known values are never exempt in the
  egress check.
- A valid checkpoint past the end of the log now forces `status` `prefix` (reason `cut_off`) even when another
  checkpoint reaches the last record.
- `shown` is a hiding commitment: the digest now includes a secret nonce the vault keeps for the handle, so a card's last
  four digits cannot be brute-forced from it. `verify_log` with the vault recomputes it.
- `call` follows RFC 8785 for integers past 2^53 in Python as in TypeScript. Arguments with no canonical form (lone
  surrogates, NaN, infinity) are refused before any fill with the new code `malformed`, with or without a log.
- `opn mcp-gateway --log-dir` writes each run to its own `<log-dir>/<session-id>/` folder.
- The TypeScript log writes every byte or throws, so a short write is never followed by a fill.
- Spec: revealing handles for display is not a release and writes no record.

### Changed

- `verify_log` returns more keys (`releases`, `proven_to`, `status`, `reason`); the old ones are as before.
- The stream restorer never cuts a sensitive reference in half.

### Planted defects (each fails a unit test and a vector in both SDKs)

A failed audit write that is swallowed; allowed releases never recorded; the real-value check skipped on release
records; an anchor past the end ignored; a head mismatch ignored; an anchor signed by the writer's key accepted; masking
inside a reference; restoring inside a reference; a stream that cuts a reference in half; a reference reported as a value the
model wrote; a refused approval not recorded; the `call` digest check skipped.

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
