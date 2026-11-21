# Secret handles: hide when reading, fill when typing

Some values the model never needs to read, only to move: a one-time code from an email into a login box, a card
number into a checkout form, an API key into a config file. For these, the model gets a handle instead of the value.

## What happens

1. The agent reads an email: "Your Acme verification code is 482913. It expires in 10 minutes."
2. `Session.mask` (or the proxy, or the MCP middleware) replaces the code with `{{OTP_1}}` and binds it to the site
   the app says the email came from:

   ```python
   masked = s.mask(email_text, Source(sender="no-reply@acme.com"))  # from a verified sender, not from the text
   ```

3. The model is told only what it needs:
   `{{OTP_1}} is a 6-digit one-time code from acme.com, valid until 14:32 UTC. Write {{OTP_1}} exactly where the
   value is needed; the real value is filled in outside the model.`
4. The model plans: "type {{OTP_1}} into #code".
5. Your code fills it, with the place it is really going:

   ```python
   s.resolve_args({"selector": "#code", "text": "{{OTP_1}}"}, Sink(tool="browser_type", site=page.url))
   ```

   or, in a real browser, `await HandleFiller(s).fill(page.locator("#code"), "{{OTP_1}}")`, which reads the site from
   the frame that holds the field.

## The checks, in order

| Check | Refusal reason |
|---|---|
| The handle exists in this session | `unknown handle` (`unknown_handle`) |
| It is bound to a site or a tool at all (fail closed) | `not bound to a site or tool` (`unbound`) |
| Not past its expiry (the policy's `ttl_s`; a phrase like "expires in 5 minutes" can only shorten it) | `expired` (`expired`) |
| Uses left (codes: one) | `already used` (`used_up`) |
| The tool is in the policy's `tools` list, if there is one | `not allowed for this tool` (`wrong_tool`) |
| The sink's host is exactly the bound host (or matches a `*.example.com` entry the policy lists) | `bound to a different site` (`wrong_site`) |
| `ask` is set, or this is a new tool and site pair and you registered `approve` | `needs the person's approval` (`needs_approval`) / `not approved` (`not_approved`) |

The code in brackets is `HandleRefused.code`. It never changes; the text may. A release log adds one more:
`release not recorded` (`not_recorded`).

If any handle in a call fails, nothing in that call is filled. The browser filler also checks that the value is not
showing in the page afterwards, clears the field if it is, and masks filled fields in screenshots.

## Who allowed it

Give the session a log and every decision is signed into it before the value is filled in:

```python
from open_pseudonym import Approval, EgressLog, Session, Signer

log = EgressLog("log", Signer.generate(), store_payloads=False)
s = Session("browse_and_fill", release_log=log,
            approve=lambda handle, what, sink: Approval(True, by="mia", channel="app"))
```

`approve` may still return `True` or `False`. Returning an `Approval` puts who and where into the record; with `ref` and
`digest` (an OAC Consent's id and token digest) the record names the consent that allowed it. The record holds the
handle, the tool, the site as a host, a digest of the call with the handle still in it, what the approver was shown
(`shown`), and never the value or a hash of it. If the log cannot be written, the call is refused with `not_recorded`
and nothing is filled. See spec 10.4.

A release record proves a decision and who made it. It does not prove the value stayed at that site.

## Rules of thumb

- Set `Source` and `Sink` from facts your app trusts: a DKIM-verified sender, the browser's real URL, the tool's fixed
  target. Never from text the model wrote or read.
- Give `approve` a real person on the other end for anything that moves money or identity documents.
- The model may write `{{OTP_1}}` into a message to someone else. `resolve_args` refuses that, because the message
  tool's sink is not the bound host. Listing `tools` in the policy narrows it further.
- Cards and bank details ask every time (the starter profiles set `ask`); wire `approve` to a real person.
- A code from accounts.example.com does not fill on login.example.com unless the policy says `*.example.com` on
  purpose: subdomains can belong to other people (user pages, shared forms).
