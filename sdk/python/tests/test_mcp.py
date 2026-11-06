"""MCP: a real MCPServer behind the middleware, and the gateway in front of an unchanged server."""

import json

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
    mw = PseudonymMiddleware(s, tool_sites={"type_code": "https://acme.com/login"},
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


def mail_server_with_extras(received: list, middleware=()):
    server = mail_server(received, middleware)

    @server.resource("mail://latest")
    def latest() -> str:
        """The newest email."""
        return INBOX

    @server.prompt()
    def reply_to_latest() -> str:
        """A prompt that quotes the newest email."""
        return "Reply to this:\n" + INBOX

    return server


@pytest.mark.anyio
async def test_resources_and_prompts_are_masked_too():
    """Critic finding: resources/read and prompts/get used to pass through untouched."""
    s = Session("strict", Vault(seed=bytes(32)))
    async with Client(mail_server_with_extras([], [PseudonymMiddleware(s)])) as client:
        res = await client.read_resource("mail://latest")
        prompt = await client.get_prompt("reply_to_latest", {})
    seen = res.contents[0].text + prompt.messages[0].content.text
    assert "Dana" not in seen and "dana.reyes" not in seen and "482913" not in seen


@pytest.mark.anyio
async def test_gateway_forwards_resources_masked_and_never_fills_unbound_handles():
    received = []
    s = Session("browse_and_fill", Vault(seed=bytes(32)))
    async with Client(mail_server_with_extras(received)) as upstream:
        async with Client(build_gateway(upstream, s, tool_sites={"type_code": "https://login.acme.com"})) as client:
            res = await client.read_resource("mail://latest")
            assert "482913" not in res.contents[0].text
            await client.call_tool("read_inbox", {})
            r = await client.call_tool("type_code", {"code": "{{OTP_1}}"})
    assert r.is_error and "not bound" in text_of(r)  # no source was given, so the code goes nowhere
    assert received == []


@pytest.mark.anyio
async def test_a_result_with_data_masking_missed_is_withheld():
    from mcp.server.mcpserver import MCPServer

    server = MCPServer("odd", middleware=[PseudonymMiddleware(Session("strict", Vault(seed=bytes(32))))])

    @server.tool()
    def lookup() -> dict:
        """Structured data keyed by an id field we never mask."""
        return {"id": "SSN 123-45-6789"}

    async with Client(server) as client:
        r = await client.call_tool("lookup", {})
    assert "123-45-6789" not in json.dumps(r.model_dump(mode="json"))
