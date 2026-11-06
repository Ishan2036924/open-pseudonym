# MCP

## Someone else's server, unchanged

```bash
pip install "open-pseudonym[mcp]"
opn mcp-gateway --profile browse_and_fill --source-site example.com \
  --tool-site submit_code=https://login.example.com -- npx some-mcp-server
```

Point your MCP host (a desktop assistant, an IDE) at the gateway command instead of the server's. The gateway lists
the server's tools, resources and prompts as they are, masks every tool result, resource and prompt before the host
and its model see them, and restores arguments before they reach the server.

`--source-site` says which site the secrets read through this server belong to; `--tool-site` says which tool acts on
which site. A handle is filled only into a tool whose site matches. Without them, handles are never filled: that is
on purpose, so a code read from an email cannot be pasted into, say, a send-email tool.

Only name tools whose target never changes (a tool that always posts to one login endpoint). A browser
tool can be steered to any page, so for browsers use `HandleFiller`, which reads the real page URL at fill time. `--vault file` keeps fakes consistent between runs (it needs `opn keygen`).

## Your own server

```python
from mcp.server.mcpserver import MCPServer
from open_pseudonym import Session, Source
from open_pseudonym.mcp import PseudonymMiddleware

session = Session("draft_reply")
server = MCPServer("mail", middleware=[PseudonymMiddleware(
    session,
    tool_sites={"submit_code": "https://login.example.com"},           # fixed-target tools only, never a browser
    source_for=lambda tool, result: Source(sender=verified_sender(result)),  # from data you trust
)])
```

For a server with many users, pass a function instead of a session: `PseudonymMiddleware(lambda ctx: session_for(ctx))`.

## What the host sees

- Text content and `structuredContent` are masked; embedded text resources, `resources/read` and `prompts/get` too.
- If a result produced handles, one more text item explains them ("Note: {{OTP_1}} is a 6-digit code...").
- A refused handle comes back as a tool error: `Not filled in: bound to a different site.`
- Every masked result goes through the egress check; one that still holds personal data comes back as an error
  ("Withheld: ...") instead. There are no receipts on this path; use the proxy for those.

The gateway protects tool data. What the person types into the host goes to the model as the host sends it; pair the
gateway with the proxy if the host lets you set its model endpoint.
