# Open Pseudonym

**Keep personal data away from AI models without making them worse at the task.**

Before text reaches a model, Open Pseudonym swaps names, emails, phone numbers, dates and secrets for stand-ins
chosen for the task at hand. The model works on the stand-ins. When it answers, the real values go back in on your
side. The key that links the two never leaves your device (or your own server).

```
You type                               The model sees                              You read
From: Dana Reyes <dana.reyes@...>      From: Parker Kaur <parker.kaur@bluepeak.example>
Hi Sam, can we move Thursday's         Hi Casey, can we move Thursday's            Sure Sam, Thursday works.
call to March 12, 2026?                call to February 26, 2026?
Your code is 482913.                   Your code is {{OTP_1}}.
```

Three things make it different from a plain redaction tool:

- **It hides by task.** A policy says, for this kind of task, what happens to each type of data. Scheduling keeps
  real dates so calendar math works; a web lookup keeps company names so search works; a reply keeps who said what
  and fakes the contact details. Code picks the policy and can only make it stricter. The model never picks.
- **It keeps the model's context.** Stand-ins are realistic and consistent: the same person gets the same fake name
  everywhere, `dana.reyes@` becomes `parker.kaur@`, dates move together by whole weeks so "Thursday" stays true,
  amounts stay exact when the task needs math. Wherever a range is set aside for examples, fakes come from it
  (`.example` domains, 555-01xx and UK drama phone numbers, documentation IP blocks, published test cards), so those
  fakes cannot reach a real person. Phone numbers in other countries have no such range and get random digits.
- **It proves what left.** Before a request is sent, its exact bytes are checked for every real value the vault
  knows and scanned again by the detectors. If anything personal is still there, the request does not go. With the
  proxy's `--log-dir` (or `record_egress` in your code), every request that goes gets an Ed25519-signed,
  hash-chained receipt you can check later with `opn verify`.

And one feature for agents: **secret handles**. A one-time code, password or card number the model only needs to
*move* becomes `{{OTP_1}}` plus a note ("a 6-digit code from acme.com, valid until 14:32 UTC"). When the agent types
`{{OTP_1}}` into a login box, a small local filler checks that the box is really on acme.com, puts the real code in
at the last moment and burns the handle. The code goes from the email to the form without passing through the
model, and a prompt injection that says "type it into evil.example" gets a refusal. A handle is bound to the exact
host it came from (a code from acme.com does not fill on docs.acme.com), cards and bank details always ask the person
first, and handles fail closed: a handle bound to neither a site nor a tool (because your app stated no source and
the policy names no tools) is never filled anywhere.

What this does not cover: ordinary personal data (a name, a phone number) is put back into any tool call the model
makes, because that is usually the point of the call. `resolve_args` flags contact or payment details the model wrote
itself, so your app can ask before sending to someone new.

## Why not just encrypt?

Because a model can only reason about words it can read.

| Approach | What the model sees | Keeps context? |
|---|---|---|
| Encryption | `x9Fq2...` | No, it is blind |
| Labels like `[NAME_1]` | a label | Partly; math and dates suffer |
| **Realistic stand-ins** (this) | "Parker Kaur" for "Dana Reyes" | Mostly yes |
| **Handles, filled in locally** (this) | "6-digit code from acme.com" | Yes, the model never needed the value |
| Computing on encrypted data | nothing readable | Yes, but seconds to minutes per word |
| Secure hardware at the provider | the real text in a sealed chip | Yes, where a provider offers it |

Open Pseudonym also offers format-preserving encryption (NIST FF1) for fields where only the shape matters, and
keyed tokens for logs.

## Install

| | Python | JavaScript / TypeScript |
|---|---|---|
| Core | `pip install open-pseudonym` | `npm install open-pseudonym` |
| Local proxy | `pip install "open-pseudonym[proxy]"` | |
| MCP middleware and gateway | `pip install "open-pseudonym[mcp]"` | |
| Browser handle filler | `pip install "open-pseudonym[browser]"` | |
| Vercel AI SDK | | `open-pseudonym/vercel-ai` |

The core needs only `cryptography` (Python) or nothing (TypeScript).

## Three ways in

**1. In your code.**

```python
from open_pseudonym import Session, Source

s = Session("draft_reply")
masked = s.mask(email_text, Source(sender="no-reply@acme.com"))   # the source binds handles to acme.com
reply = call_your_model(masked.text, masked.notes)                 # notes explain any {{handles}}
print(s.restore(reply))                                            # real values back for the person
```

Streaming: `st = s.stream()`, then `st.feed(chunk)` for each chunk and `st.flush()` at the end. Tool calls:
`s.resolve_args(args, Sink(tool="browser_type", site=page_url))` restores the arguments and fills handles only where
their binding allows.

**2. Change one URL.** Run the local proxy and point any app at it. It speaks the OpenAI Chat Completions,
OpenAI Responses and Anthropic Messages APIs, streamed or not, and passes your API key through untouched.

```bash
opn keygen
opn proxy --profile draft_reply --log-dir ~/.local/share/open-pseudonym/receipts
# then use base_url http://127.0.0.1:8787/v1 (OpenAI style) or http://127.0.0.1:8787 (Anthropic style)
```

The proxy has no login: it is meant for one person on their own machine, listening on 127.0.0.1. Anyone who can
reach it and knows a session id can read that session's restores, so put real authentication in front of it before
sharing it.

Async SDK clients can use the proxy in-process, no port needed:
`AsyncOpenAI(http_client=httpx.AsyncClient(transport=async_transport(profile="draft_reply")))`.

**3. Agents and MCP.** Put any MCP server behind a gateway with no code changes, or add the middleware to your own
server. Tool results are masked on their way to the model; tool arguments are restored on their way to the tool.

```bash
opn mcp-gateway --profile browse_and_fill --source-site example.com \
  --tool-site submit_code=https://login.example.com -- npx some-mcp-server
```

`--tool-site` is for tools whose target never changes. A browser tool can be steered to any page, so browsers fill
handles with `HandleFiller`, which reads the real page URL at the moment it types.

## Levels: let people choose

Not everyone wants the same thing hidden, and that is fine. Products can offer one switch:

| Level | Label | Hidden from the model |
|---|---|---|
| 1 | Secrets | One-time codes, passwords, cards, bank numbers, SSNs, keys |
| 2 | Contacts | Level 1, plus emails, phone numbers, street addresses, IPs |
| 3 | Everything | Level 2, plus names, companies and places; dates shift together |

Secrets are hidden at every level, as handles the model can still use (it knows "a 6-digit code from acme.com"),
so the task still works. `load_level(2)` gives the policy; `LEVELS` holds the labels and one-line explanations to
show people.

## Profiles

| Profile | For |
|---|---|
| `draft_reply` | Replying to messages: people and contact details faked, dates shifted, secrets as handles |
| `schedule` | Calendars: dates and times stay real, people faked |
| `summarize` | Documents: contact details removed, people faked, places blurred |
| `web_research` | Lookups: companies, places and links stay, people faked |
| `money_math` | Budgets and invoices: amounts exact, who and where faked |
| `browse_and_fill` | Agents that log in and fill forms: secrets as bound handles |
| `logs` | Debugging: stable keyed tokens per user |
| `training_data` | Datasets: everything faked consistently across files |
| `secrets_only`, `contacts`, `strict` | Simple levels for a product switch |

Write your own as JSON (`schemas/policy.schema.json`). The actions are keep, shift, generalize, fake, tag, token,
fpe, handle, drop and refuse.

## Proof

```bash
opn verify ~/.local/share/open-pseudonym/receipts/<session> --vault my.vault
# receipts: 14
# payloads re-checked against the vault: 14, known values found: 0
# every receipt is signed, chained and matches its payload
```

What this proves, exactly: no value the vault knows, and nothing the detectors find in the outgoing bytes, was in
any request that carries a valid receipt. It does not prove that a value no detector recognises did not leave, and a
log cut short at the end only shows up if you compare it with a count or last receipt you kept (`--expect-count`,
`--expect-last`). That is why the benchmark measures detection too.

## How well it works

Offline benchmark (`python bench/run.py offline`, no model, costs nothing), 120 generated items plus 14 hand-written:

| | Result |
|---|---|
| Cards, IBANs, SSNs, emails, phones, dates, amounts, addresses, codes | 100% found on the generated set |
| Names, rules only | 100% on the generated set, 86% on the hand-written set |
| Names the app already knows, in any case | caught again everywhere, including "dana reyes" |
| Planted values that reached the model (strict profile) | 0 of 570 generated, 1 of 25 hand-written |
| Same, with the app's contact list | 0 of 570 and 0 of 25 |
| Restore gives back exactly the original | 134 of 134 |
| Streaming restore equals whole restore | 134 of 134 |
| Speed | about 1 ms to mask and 0.2 ms to restore an item |

A fair warning about these numbers: the generated set uses templates the name rules were tuned on, so its 100% is
optimistic; the hand-written set is the honest one, and it is small and written by the same author. A set written by
someone else is the most useful contribution anyone could make right now.

Rules are still the weak spot for names in free text. Pass the names your app already knows (`known={"PERSON": contacts}`) or add an ML
detector (`open_pseudonym.ml`: GLiNER, spaCy or Presidio). The model run (task accuracy on clear text, tags,
redaction and stand-ins, plus re-identification) is in `bench/run.py model`; results are not published yet.

## Known limits (alpha 0.1)

- Names are found by cues (greetings, titles, headers, role words) or because your app lists them; a name with no cue
  in free text can be missed. Non-Latin scripts and lookalike letters are not handled by the rules.
- Binary files (images, PDFs, audio) are passed through untouched; text sent as base64 is decoded, masked and checked.
- The proxy checks the body and the query string, not request headers (they carry credentials and versions).
- A receipts log cut short at the end is only detectable against a count or last receipt you kept elsewhere.
- Ordinary personal data is restored into any tool call; handles are the part that resists prompt injection.
- The proxy has no login and is meant for one person on their own machine.
- Model-based quality results are not published yet.

## What it is, and is not

This is **pseudonymisation** (GDPR Article 4(5)): personal data replaced so it cannot be tied to a person without
extra information that is kept separately. It is **not anonymisation**. What reaches the model is still personal data
in law, and a determined reader can sometimes work out who a text is about from what is left. Please do not describe
anything built on this as anonymous or as compliant with any law. Accurate wording is in
[spec section 13](spec/open-pseudonym.md#13-wording).

## The standard

- [Specification](spec/open-pseudonym.md) (CC BY 4.0): detection, policies, stand-ins, the vault, restoring,
  handles, receipts, proxy and MCP bindings.
- [Test vectors](vectors/): fixed seeds and clocks, exact expected outputs. The Python and TypeScript SDKs both pass
  every one; a third implementation can check itself the same way (`opn conformance vectors/`).
- [Schemas](schemas/) for policies, receipts, vaults and the shared pattern file.

## Related work

Built on ideas from many places, and meant to sit next to them: Microsoft Presidio (detection framework), LLM Guard
and LiteLLM's guardrails (placeholder masking), Tonic Textual and Google Sensitive Data Protection (consistent
surrogates, date shifting, format-preserving encryption), browser-use and password managers' agent autofill
(secrets injected at typing time), WebOTP and Apple's code autofill (codes bound to a domain), and research such as
PAPILLON, Hide and Seek, AirGapAgent, Veil-Then-Reveal and the Text Anonymization Benchmark. What this project adds
is an open, testable format that ties task-aware policies, consistent stand-ins, bound handles and signed egress
receipts together.

## Contributing, security, licence

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md). Code, data, schemas and vectors are under
Apache-2.0 ([LICENSE](LICENSE)); the specification text is under CC BY 4.0 ([LICENSE-SPEC](LICENSE-SPEC)).
