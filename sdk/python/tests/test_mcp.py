"""MCP: a real MCPServer behind the middleware, and the gateway in front of an unchanged server."""

import pytest

pytest.importorskip("mcp")

from mcp import Client  # noqa: E402
from mcp.server.mcpserver import MCPServer  # noqa: E402

from open_pseudonym import Session, Source, Vault  # noqa: E402
from open_pseudonym.mcp import PseudonymMiddleware, build_gateway  # noqa: E402

INBOX = "From: Dana Reyes <dana.reyes@gmail.com>\nYour Acme verification code is 482913."


def mail_server(received: list, middleware=()):
    server = MCPServer("mail", middleware=list(middleware))

    @server.tool()
    def read_inbox() -> str:
        """Read the newest email."""
        return INBOX

    @server.tool()
    def send_email(to: str, body: str) -> str:
        """Send an email."""
        received.append({"to": to, "body": body})
        return f"sent to {to}"

    @server.tool()
    def type_code(code: str) -> str:
        """Type a code into the login page."""
        received.append({"code": code})
        return "typed"

    return server


def text_of(result):
    return "\n".join(b.text for b in result.content if getattr(b, "type", "") == "text")


@pytest.mark.anyio
async def test_middleware_masks_results_and_restores_arguments():
    received = []
    s = Session("browse_and_fill", Vault(seed=bytes(32)))
    mw = PseudonymMiddleware(s, site="https://login.acme.com",
                             source_for=lambda tool, result: Source(sender="no-reply@acme.com"))
    async with Client(mail_server(received, [mw])) as client:
        inbox = text_of(await client.call_tool("read_inbox", {}))
        assert "Dana" not in inbox and "482913" not in inbox and "{{OTP_1}}" in inbox
        assert "Note: {{OTP_1}} is a 6-digit one-time code from acme.com" in inbox
        fake_email = inbox.split("<")[1].split(">")[0]
        sent = await client.call_tool("send_email", {"to": fake_email, "body": "On it"})
        assert "dana.reyes" not in text_of(sent)  # the confirmation that comes back is masked again
        await client.call_tool("type_code", {"code": "{{OTP_1}}"})
        again = await client.call_tool("type_code", {"code": "{{OTP_1}}"})
    assert received == [{"to": "dana.reyes@gmail.com", "body": "On it"}, {"code": "482913"}]
    assert again.is_error and "already used" in text_of(again)


@pytest.mark.anyio
async def test_middleware_refuses_a_handle_for_the_wrong_site():
    received = []
    s = Session("browse_and_fill", Vault(seed=bytes(32)))
    mw = PseudonymMiddleware(s, site="https://evil.example",
                             source_for=lambda tool, result: Source(sender="no-reply@acme.com"))
    async with Client(mail_server(received, [mw])) as client:
        await client.call_tool("read_inbox", {})
        r = await client.call_tool("type_code", {"code": "{{OTP_1}}"})
    assert r.is_error and "bound to a different site" in text_of(r)
    assert received == []


@pytest.mark.anyio
async def test_gateway_wraps_an_unchanged_server():
    received = []
    upstream_server = mail_server(received)  # no middleware: the server knows nothing about us
    s = Session("draft_reply", Vault(seed=bytes(32)))
    async with Client(upstream_server) as upstream:
        gateway = build_gateway(upstream, s)
        async with Client(gateway) as client:
            tools = {t.name for t in (await client.list_tools()).tools}
            assert tools == {"read_inbox", "send_email", "type_code"}
            inbox = text_of(await client.call_tool("read_inbox", {}))
            assert "Dana" not in inbox and "dana.reyes" not in inbox
            fake_email = inbox.split("<")[1].split(">")[0]
            await client.call_tool("send_email", {"to": fake_email, "body": "hello"})
    assert received == [{"to": "dana.reyes@gmail.com", "body": "hello"}]
