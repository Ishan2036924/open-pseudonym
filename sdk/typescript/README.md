# open-pseudonym (JavaScript / TypeScript)

Keep personal data away from AI models without making them worse at the task. Before text goes to a model, names,
emails, phone numbers, dates and secrets are swapped for realistic stand-ins. When the model answers, the real values
go back in on your side. The vault that links the two never leaves your process.

This is the TypeScript SDK of [Open Pseudonym](https://github.com/Ishan2036924/open-pseudonym). It follows the
spec and passes the same shared test vectors as the Python SDK, so the same seed and clock give the same stand-ins,
the same masked text and the same signed receipts in both.

It is pseudonymisation, not anonymisation. Text that went through it is still personal data for whoever holds the
vault, so do not describe it as anonymous.

```
npm install open-pseudonym
```

Needs Node 23.6 or newer. No runtime dependencies (only `node:crypto`, `node:fs` and `node:path`).

## Quickstart

```ts
import { Session, Source, Sink } from "open-pseudonym";

const session = new Session("draft_reply");

// What the model may see. The source binds any secret to the site it came from.
const masked = session.mask(emailText, new Source({ sender: "no-reply@acme.com" }));
const answer = await callYourModel(masked.text, masked.notes); // notes explain any {{handles}}

// What the person reads.
console.log(session.restore(answer));
```

Things to know:

- A profile (`"draft_reply"`, `"strict"`, ...) says what happens to each type of data. See `profileNames()`.
  A policy can be made stricter in code (`tighten`, `withRules`) but never looser.
- Names are found next to a cue ("From:", "Hi", "Mr.") or when you list them:
  `new Session("strict", { known: { PERSON: ["Dana Reyes"] } })`.
- Streaming: `const st = session.stream()`, then `st.feed(chunk)` for each chunk and `st.flush()` at the end.
- Tool calls: `session.resolveArgs(args, new Sink({ tool: "browser_type", site: pageUrl }))` restores the arguments
  and fills a secret handle only where its binding allows. Otherwise it throws `HandleRefused`. Give a tool a fixed
  `site` only when it always acts on one target; a browser tool can be steered to any page, so resolve with the
  page's real URL at the moment of filling.
- Handles are bound to the exact host they came from: a code mailed by `no-reply@acme.com` fills on `acme.com`, not
  on `docs.acme.com`, where anyone may host a form. A policy can allow subdomains on purpose by writing the site as
  `*.acme.com` in a handle rule's `sites`; it is never inferred. A secret whose source you did not state (no
  `Source`, or only a bare shared suffix such as `github.io`) is never filled anywhere.
- Cards, IBANs, routing numbers and bank accounts always ask first: the profiles set `ask`, so pass an
  `approve(handle, description, sink)` callback to the `Session` that asks the person, or the fill is refused.
- Levels: `loadLevel(1 | 2 | 3)` gives the policy for a simple privacy switch (1 Secrets, 2 Contacts, 3 Everything),
  and `LEVELS` holds the labels and one-line explanations to show people. Secrets are hidden at every level.
  `policyFor("schedule", 2)` combines a task's profile with a person's level; the level can only add hiding.
- Chat history and JSON: `maskMessages`, `maskJson`, `maskValue`, `restoreJson`.
- The vault: `session.vault.save(path, key)` and `Vault.load(path, key)` use AES-256-GCM with a 32-byte key you keep.
- Proof: `session.checkEgress(payload)` looks for any real value the vault knows in the exact bytes you are about to
  send, and runs the detectors over the content (every key and string of a JSON payload) for personal data that was
  never masked. `session.recordEgress(log, payload, "api.example.com")` does that check and signs a chained receipt, and
  `verifyLog(folder, publicKey, vault)` checks the log later.

Positions in `masked.replacements` are UTF-16 offsets, the way JavaScript strings are indexed.

## Vercel AI SDK

`open-pseudonym/vercel-ai` is a language-model middleware for AI SDK 7. Install `ai` next to it.

```ts
import { generateText, wrapLanguageModel } from "ai";
import { Session, Sink } from "open-pseudonym";
import { pseudonymMiddleware } from "open-pseudonym/vercel-ai";

const session = new Session("draft_reply", { known: { PERSON: ["Dana Reyes"] } });

const model = wrapLanguageModel({
  model: yourModel,
  middleware: pseudonymMiddleware({
    session,
    // where each tool's arguments are about to go, from facts your app trusts: a fixed site only for tools with a
    // fixed target, and for a browser the page's real URL at fill time
    sink: (toolName) => new Sink({ tool: toolName, site: currentPageUrl() }),
  }),
});

const { text } = await generateText({ model, prompt: "Reply to Dana Reyes about Thursday" });
```

What it does:

| Direction | What happens |
|---|---|
| Prompt to the provider | Text parts, tool-call inputs and tool results are masked. Notes about handles are added where the model first sees them. |
| Text back (`generateText`) | Stand-ins are replaced by the real values. A secret handle reads as a short description, or as the value with `revealHandles: true`. |
| Text back (`streamText`) | Each text block goes through a `StreamRestorer`, so a name split across chunks still comes back whole. |
| Tool calls | Inputs go through `resolveArgs` with the sink your app provides, so tools run on real values and handles are filled only where they belong. A refused handle throws (or, when streaming, becomes an error part and the call is dropped). |

Options: `session`, `sink`, `revealHandles`, `source` (a `Source`, or a function of the role and tool name, to bind
handles to a site), and `checkEgress`. The egress check is on by default: before the call goes out it looks in the
JSON of the masked prompt for known real values and for personal data that was never masked, and throws `EgressLeak`
if any is left. It checks that JSON, not the provider's final bytes, because the provider package may add fields of
its own afterwards. Pass `checkEgress: false` to turn it off.

What this does not cover: ordinary personal data (a name, a phone number) is put back into any tool call the model
makes, because that is usually the point of the call. Secret handles are the injection-proof part: they are filled
only on the host they are bound to, and cards and bank details ask the person first.

Not covered: files and images (they cannot be masked), tool definitions and provider options. Reasoning parts are
passed through untouched, because some providers sign them.

## Checking an install

```
npm test                 # shared vectors, unit tests, Vercel AI SDK tests
npm run conformance      # only the shared vectors (needs the repository checkout)
```

## Licence

Apache-2.0. The specification text is CC BY 4.0.
