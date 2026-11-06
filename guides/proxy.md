# The local proxy

The proxy speaks the providers' own APIs, so an app gets protection by changing its base URL and nothing else.

```bash
pip install "open-pseudonym[proxy]"
opn keygen
opn proxy --profile draft_reply --port 8787 --log-dir ~/.local/share/open-pseudonym/receipts
```

| App uses | Set base URL to |
|---|---|
| OpenAI Chat Completions or Responses | `http://127.0.0.1:8787/v1` |
| Anthropic Messages | `http://127.0.0.1:8787` |
| Any OpenAI-compatible server (vLLM, OpenRouter...) | start the proxy with `--openai-upstream <its URL>` |

Your API key passes through to the provider untouched. The proxy never stores it or logs it.

## Per-request headers (optional, set by your app)

| Header | Meaning |
|---|---|
| `x-opn-session` | Requests with the same id share a vault, so the same person keeps the same fake across turns. Without it, each request gets a fresh session. |
| `x-opn-profile` | Pick one of the profiles the proxy was started with `--allow-profile`. It is always combined with the base profile in the stricter direction. |
| `x-opn-source-sender`, `x-opn-source-site` | Where the text came from, for binding handles. |

Response headers: `x-opn-session`, `x-opn-receipt` (the signed receipt) and `x-opn-unknown` (stand-ins the model
invented, worth showing to a person).

## Tool calls and handles

Fakes in tool-call arguments always come back as real values. Handles come back as `{{handles}}` for your app to
resolve with `Session.resolve_args`, unless you let the proxy fill them for a tool whose target it knows:

```bash
opn proxy --profile browse_and_fill --fill-tool browser_type=https://login.example.com
```

## In-process, for async clients

```python
import httpx
from openai import AsyncOpenAI
from open_pseudonym.proxy import async_transport

client = AsyncOpenAI(http_client=httpx.AsyncClient(transport=async_transport(profile="draft_reply")))
```

Anthropic's Python SDK 2.x is built on `httpx2`: use `httpx2.AsyncClient(transport=async_transport(library="httpx2"))`.
The OpenAI Agents SDK takes an `AsyncOpenAI` client, so it works the same way.

## When a request is refused

| Status | `error.type` | Why |
|---|---|---|
| 422 | `opn_egress_refused` | A real value the vault knows was still in the request (often in a field the proxy does not mask, like `metadata`). Nothing was sent. |
| 422 | `opn_refused` | The policy says `refuse` for a type that appeared. |
| 403 | `opn_profile_refused` | The requested profile was not enabled with `--allow-profile`. |
