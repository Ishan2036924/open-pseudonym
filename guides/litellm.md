# LiteLLM guardrail

Add Open Pseudonym to a [LiteLLM proxy](https://docs.litellm.ai/docs/proxy/guardrails/custom_guardrail) with a few
lines of `config.yaml`. Every app that already talks to your LiteLLM proxy gets masking, the egress check, restored
answers and signed receipts without a code change.

```bash
pip install "open-pseudonym[litellm]"
```

Tested with LiteLLM 1.108.x. Another version logs a warning at start.

```yaml
# config.yaml
guardrails:
  - guardrail_name: open-pseudonym
    litellm_params:
      guardrail: open_pseudonym.litellm.OpenPseudonymGuardrail
      mode: [pre_call, post_call]
      default_on: true
      profile: draft_reply                 # the base policy (see Profiles in the README)
      # all optional:
      key_dir: /etc/open-pseudonym         # made by `opn keygen`: signing.pem signs, vault.key encrypts vaults
      log_dir: /var/lib/open-pseudonym/log # signed egress receipts and release records
      vault_dir: /var/lib/open-pseudonym/vaults
      allowed_profiles: [summarize]        # profiles a caller may pick with x-opn-profile (always made stricter)
      fill_tools:                          # tools whose secret handles may be filled, and the site each acts on
        submit_code: https://login.example.com
```

Keys are read from files in `key_dir`, never from `config.yaml`.

## What happens to one request

| Step | Where in LiteLLM | What it does | If it fails |
|---|---|---|---|
| 1. Mask | pre-call hook | Masks every field LiteLLM will send: messages, system prompt, tools and their descriptions, `extra_body`, Responses `input` and `instructions`, Anthropic `system`. Two passes, as the proxy does. LiteLLM's own bookkeeping fields are left alone. | Refused, HTTP 400 |
| 2. Check | pre-call hook | The egress check reads the masked request: any real value the vault knows, and a fresh detection pass for new personal data in a field masking did not cover. | Refused, HTTP 400 (`opn_egress_refused`, the types only) |
| 3. Check again, sign | deployment hook, after routing and just before the provider call | The final request is checked again, so a value added after step 1 (a deployment setting, another guardrail, a fallback) never leaves. With `log_dir`, one signed receipt per attempt, naming the deployment's host. | Refused, HTTP 400 |
| 4. Restore | post-call and streaming hooks | Text and tool-call arguments come back with real values. Streams are restored as they arrive; a stand-in split across chunks is held back until it is whole; tool-call arguments are held until their choice finishes. | The answer is not returned |

Handles (`{{OTP_1}}`) are filled only for tools listed in `fill_tools`, only where the handle's binding allows that
site, and every fill or refusal is a signed release record when `log_dir` is set. Text the model writes never decides
what is revealed.

Restoring writes into a copy of the answer. LiteLLM caches the objects it hands to hooks, so a real value written
there could reach the next caller whose masked request looks the same.

## Call types

| Call type | What happens |
|---|---|
| Chat Completions, text completions | masked, checked, restored (streamed or not) |
| Responses (`/v1/responses`) | masked, checked, restored |
| Anthropic Messages (`/v1/messages`) | masked, checked, restored |
| Embeddings | masked and checked (nothing to restore) |
| MCP tool calls and listings | left alone (not model input; see Open Action Consent for tool calls) |
| Anything else (pass-through routes, batches, files, audio, images, rerank...) | refused with `opn_unsupported_call`, unless you list it in `skip_call_types`, which lets it through unprotected |

## Request headers (optional, set by the app)

| Header | Meaning |
|---|---|
| `x-opn-session` | Requests with the same id share a vault, so a person keeps the same stand-in across turns. Needed for Responses chains that use `previous_response_id`. Without it each request is its own session. |
| `x-opn-profile` | One of `allowed_profiles`; combined with `profile` in the stricter direction. |
| `x-opn-source-sender`, `x-opn-source-site` | Where the text came from, for binding handles. |

Sessions belong to the caller: the session key is the caller's LiteLLM key identity (key, user, team, end user) plus
the session id. Another caller who sends the same `x-opn-session` gets an empty vault, not yours.

## Receipts

```bash
opn verify /var/lib/open-pseudonym/log/<session folder> --pub /etc/open-pseudonym/signing.pub.pem
```

A receipt covers the request as LiteLLM hands it to its provider adapter for that attempt. The adapter reshapes it
into the provider's format; it does not add content. For receipts over the exact bytes on the wire, point the
deployment's `api_base` at `opn proxy` instead (or as well): that is the high-assurance setup.

## Known limits

- LiteLLM keeps the original request for its own use (`proxy_server_request`, spend logs, logging callbacks) and
  records restored answers in the same places. Turn off prompt storage in spend logs
  (`general_settings: disable_spend_logs` or `store_prompts_in_spend_logs: false`) and review your logging callbacks.
- Key or team metadata `disable_global_guardrails` turns any `default_on` guardrail off for that key, this one too.
  Keep that switch to people who may send real data unmasked.
- Binary parts (images, PDFs, audio) are not inspected, as in the proxy.
- Vaults live in the LiteLLM worker's memory. With several workers, set `vault_dir` so a session finds its vault on
  any worker.
- LiteLLM changes quickly. The deployment-hook re-check and the stream hooks depend on LiteLLM internals; the pre-call
  mask and check use its documented guardrail hook. Pin the version you tested.
