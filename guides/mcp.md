# MCP

## Someone else's server, unchanged

```bash
pip install "open-pseudonym[mcp]"
opn mcp-gateway --profile browse_and_fill --site https://login.example.com -- npx some-mcp-server
```

Point your MCP host (a desktop assistant, an IDE) at the gateway command instead of the server's. The gateway lists
the server's tools as they are, masks every tool result before the host and its model see it, and restores
arguments before they reach the server. `--vault file` keeps fakes consistent between runs (it needs `opn keygen`).

## Your own server

```python
from mcp.server.mcpserver import MCPServer
from open_pseudonym import Session, Source
from open_pseudonym.mcp import PseudonymMiddleware

session = Session("draft_reply")
server = MCPServer("mail", middleware=[PseudonymMiddleware(
    session,
    site="https://mail.example.com",                                   # what the tools act on, for handles
    source_for=lambda tool, result: Source(sender=verified_sender(result)),  # from data you trust
)])
```

For a server with many users, pass a function instead of a session: `PseudonymMiddleware(lambda ctx: session_for(ctx))`.

## What the host sees

- Text content and `structuredContent` are masked; embedded text resources too.
- If a result produced handles, one more text item explains them ("Note: {{OTP_1}} is a 6-digit code...").
- A refused handle comes back as a tool error: `Not filled in: bound to a different site.`

The gateway protects tool data. What the person types into the host goes to the model as the host sends it; pair the
gateway with the proxy if the host lets you set its model endpoint.
