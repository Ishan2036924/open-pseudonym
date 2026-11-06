"""Open Pseudonym for MCP: tool results are masked on their way to the model, tool arguments are restored on their
way to the tool. Needs the [mcp] extra: pip install "open-pseudonym[mcp]".

Two ways in:

  - Your own server: add the middleware.

        server = MCPServer("mail", middleware=[PseudonymMiddleware(Session("draft_reply"))])

  - Someone else's server, unchanged: run the gateway in front of it.

        opn mcp-gateway --profile browse_and_fill -- npx some-mcp-server

The model only ever sees stand-ins. When it calls a tool, fakes turn back into real values and secret handles are
filled in only if the handle's binding allows that tool and its site. A refused handle comes back to the model as a
tool error carrying the short reason ("bound to a different site"), never the value.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any, Callable

try:
    from mcp import Client
    from mcp.server.lowlevel.server import Server
    from mcp.server.stdio import stdio_server
    from mcp_types import CallToolRequestParams, CallToolResult, TextContent
except ImportError as e:  # the optional dependency is not installed
    raise ImportError('open_pseudonym.mcp needs the MCP SDK: pip install "open-pseudonym[mcp]"') from e

from ..handles import HandleRefused, Sink, Source
from ..session import Session

SourceFor = Callable[[str, Any], "Source | None"]


def _refused(reason: str) -> CallToolResult:
    return CallToolResult(content=[TextContent(type="text", text=f"Not filled in: {reason}.")], is_error=True)


class PseudonymMiddleware:
    """MCP server middleware (works on MCPServer and the low-level Server).

    session:    the Session to use, or a callable that picks one per request (multi-user servers)
    site:       the site this server acts on (its tools' target), used as the sink for handles
    tool_sites: per-tool sites when different tools act on different sites
    source_for: given (tool name, raw result), the Source of what the tool returned; set it only from facts the
                server trusts (a verified email sender), never from the result's text
    """

    def __init__(self, session: Session | Callable[[Any], Session], *, site: str | None = None,
                 tool_sites: dict[str, str] | None = None, source_for: SourceFor | None = None):
        self._session = session if callable(session) and not isinstance(session, Session) else (lambda ctx: session)
        self.site = site
        self.tool_sites = dict(tool_sites or {})
        self.source_for = source_for

    async def __call__(self, ctx, call_next):
        if ctx.method != "tools/call" or not isinstance(ctx.params, dict):
            return await call_next(ctx)
        s = self._session(ctx)
        params = dict(ctx.params)
        name = params.get("name", "")
        try:
            resolved = s.resolve_args(params.get("arguments") or {}, Sink(tool=name, site=self.tool_sites.get(name, self.site)))
        except HandleRefused as exc:
            return _refused(exc.reason)
        params["arguments"] = resolved.args
        result = await call_next(replace(ctx, params=params))
        return mask_result(s, result, self.source_for(name, result) if self.source_for else None)


def mask_result(s: Session, result: Any, source: Source | None = None) -> Any:
    """Mask a tools/call result: text content, embedded text resources and structured content."""
    if result is None:
        return result
    model = result if isinstance(result, CallToolResult) else CallToolResult.model_validate(result)
    notes: list[str] = []
    content = []
    for block in model.content:
        if getattr(block, "type", None) == "text":
            m = s.mask(block.text, source)
            notes.extend(n for n in m.notes if n not in notes)
            content.append(block.model_copy(update={"text": m.text}))
        elif getattr(block, "type", None) == "resource" and hasattr(block.resource, "text"):
            m = s.mask(block.resource.text, source)
            notes.extend(n for n in m.notes if n not in notes)
            content.append(block.model_copy(update={"resource": block.resource.model_copy(update={"text": m.text})}))
        else:
            content.append(block)
    structured = model.structured_content
    if structured is not None:
        structured, more = s.mask_json(structured, source)
        notes.extend(n for n in more if n not in notes)
    if notes:
        content.append(TextContent(type="text", text="\n".join("Note: " + n for n in notes)))
    return model.model_copy(update={"content": content, "structured_content": structured})


def build_gateway(upstream: Client, session: Session, *, name: str = "open-pseudonym-gateway",
                  site: str | None = None, tool_sites: dict[str, str] | None = None,
                  source_for: SourceFor | None = None) -> Server:
    """A server that re-exposes `upstream`'s tools with the middleware in front. `upstream` must be connected."""

    async def list_tools(ctx, params):
        return await upstream.list_tools()

    async def call_tool(ctx, params: CallToolRequestParams):
        return await upstream.call_tool(params.name, params.arguments or {})

    server = Server(name, on_list_tools=list_tools, on_call_tool=call_tool)
    server.middleware.append(PseudonymMiddleware(session, site=site, tool_sites=tool_sites, source_for=source_for))
    return server


async def run_gateway(upstream_target: Any, session: Session, **kw) -> None:
    """Connect to the upstream server (a URL or StdioServerParameters) and serve the gateway over stdio."""
    async with Client(upstream_target) as upstream:
        server = build_gateway(upstream, session, **kw)
        async with stdio_server() as (read, write):
            await server.run(read, write, server.create_initialization_options())


__all__ = ["PseudonymMiddleware", "build_gateway", "mask_result", "run_gateway"]
