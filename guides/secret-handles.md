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
| The handle exists in this session | `unknown handle` |
| Not past its expiry (codes: from "expires in N minutes", else the policy's `ttl_s`) | `expired` |
| Uses left (codes: one) | `already used` |
| The tool is in the policy's `tools` list, if there is one | `not allowed for this tool` |
| The sink's host is the bound site or a subdomain of it | `bound to a different site` |
| `ask` is set, or this is a new tool and site pair and you registered `approve` | `needs the person's approval` / `not approved` |

If any handle in a call fails, nothing in that call is filled. The browser filler also checks that the value is not
showing in the page afterwards, clears the field if it is, and masks filled fields in screenshots.

## Rules of thumb

- Set `Source` and `Sink` from facts your app trusts: a DKIM-verified sender, the browser's real URL, the tool's fixed
  target. Never from text the model wrote or read.
- Give `approve` a real person on the other end for anything that moves money or identity documents.
- The model may write `{{OTP_1}}` into a message to someone else. `resolve_args` refuses that unless the policy's
  `tools` or `sites` allow it, which is why browse-and-fill profiles should list their tools.
