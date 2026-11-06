# Python quick reference

```python
from open_pseudonym import Session, Source, Sink, Vault, load_profile

s = Session("draft_reply", known={"PERSON": ["Dana Reyes", "Sam Okafor"]})   # your contacts make names reliable
m = s.mask(text, Source(sender="no-reply@acme.com"))
m.text          # what the model may see
m.notes         # one line per handle, to send along with the text
m.replacements  # where each stand-in went, its type and action

s.restore(answer)                        # real values back; handles become short labels
s.restore(answer, reveal_handles=True)   # the person's own view, secrets included
st = s.stream(); st.feed(chunk); st.flush()
s.resolve_args(tool_args, Sink(tool="send_email"))   # before a tool runs
s.check_egress(request_bytes)            # [] means no known value is in there
s.mask_messages(chat_messages)           # OpenAI or Anthropic message lists
s.mask_json(tool_result)                 # any JSON value
```

**Policies.** `load_profile(name)`, `Policy.from_dict(doc)`, `p.tighten(other)`, `p.with_rules({...})`. Loosening
raises `PolicyError`. `suggest_profile(tool_names)` gives advice for the app, never for the model to act on.

**Vaults.** `Vault()` makes a fresh random one. `vault.save(path, key)` and `Vault.load(path, key)` use AES-256-GCM
with a 32-byte key you keep elsewhere (`opn keygen` makes one). One vault per conversation is typical; share one
across a dataset for consistent fakes, or pin `vault.token_key` to keep `token` stand-ins stable across vaults.

**Receipts.** `log = EgressLog(folder, Signer.generate())`, then `s.record_egress(log, request_bytes, "api.example.com")`
before each send. It raises `EgressLeak` instead of letting a known value out. `verify_log(folder, public_key, vault)`
checks the lot.

**Names.** Rules catch names after greetings, titles, mail headers, sign-offs and some verbs. For everything else pass
`known=` lists or an ML detector from `open_pseudonym.ml` (GLiNER, spaCy, Presidio).
