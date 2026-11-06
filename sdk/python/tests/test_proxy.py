"""The proxy, end to end, against a fake upstream that records exactly what it received."""

import json
import re

import httpx
import pytest

pytest.importorskip("starlette")

from open_pseudonym import Signer, verify_log  # noqa: E402
from open_pseudonym.jws import verify  # noqa: E402
from open_pseudonym.proxy import ProxyConfig, create_app  # noqa: E402

MAIL = "From: Dana Reyes <dana.reyes@gmail.com>\nHi Sam,\nCall (617) 555-0142. Your Acme verification code is 482913."
# exact real values; a random fake may reuse an area code like 617 or a name like Sami, which is fine
REAL = ["Dana", "Reyes", "dana.reyes", "(617) 555-0142", "482913", "Hi Sam,"]


class Upstream:
    """Records requests and answers with whatever the test hands it, built from the masked request."""

    def __init__(self, answer):
        self.answer = answer
        self.seen = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        self.seen.append({"url": str(request.url), "headers": dict(request.headers), "body": body,
                          "raw": request.content.decode()})
        return self.answer(body)


def fake_name(body):
    text = json.dumps(body)
    return re.search(r"From: ([A-Z][a-z]+) ([A-Z][a-z]+) <", text).groups()


def client_for(upstream, tmp_path=None, **kw):
    signer = Signer.from_seed(bytes(32))
    cfg = ProxyConfig(profile=kw.pop("profile", "draft_reply"), transport=httpx.MockTransport(upstream),
                      signer=signer, log_dir=str(tmp_path) if tmp_path else None, **kw)
    app = create_app(cfg)
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://proxy"), signer


def sse(*events, done=True):
    out = "".join(f"data: {json.dumps(e)}\n\n" for e in events)
    return out + ("data: [DONE]\n\n" if done else "")


@pytest.mark.anyio
async def test_chat_masks_request_and_restores_answer(tmp_path):
    def answer(body):
        first, last = fake_name(body)
        content = f"Hi {first}, I will call {first} {last} back."
        return httpx.Response(200, json={"id": "c1", "object": "chat.completion",
                                         "choices": [{"index": 0, "message": {"role": "assistant", "content": content},
                                                      "finish_reason": "stop"}]})

    up = Upstream(answer)
    client, signer = client_for(up, tmp_path)
    async with client:
        r = await client.post("/v1/chat/completions", headers={"authorization": "Bearer test-key",
                                                               "x-opn-session": "s1"},
                              json={"model": "m", "messages": [{"role": "user", "content": MAIL}]})
    assert r.status_code == 200, r.text
    assert r.json()["choices"][0]["message"]["content"] == "Hi Dana, I will call Dana Reyes back."
    sent = up.seen[0]
    assert all(v not in sent["raw"] for v in REAL)
    assert sent["headers"]["authorization"] == "Bearer test-key"  # the app's credentials pass through untouched
    assert "x-opn-session" not in sent["headers"]
    assert "Note: {{OTP_1}} is a 6-digit one-time code" in sent["raw"]
    body = verify(r.headers["x-opn-receipt"], signer.public_key, "opn-egress+jws")
    assert body["check"]["found"] == 0 and body["dest"] == "api.openai.com"
    assert verify_log(tmp_path / "s1", signer.public_key)["problems"] == []


@pytest.mark.anyio
async def test_chat_stream_restores_split_names_and_tool_calls():
    def answer(body):
        first, last = fake_name(body)
        email = re.search(r"<([^>]+)>", json.dumps(body))[1]
        text = f"Sure {first} {last}, done."
        pieces = [text[i:i + 3] for i in range(0, len(text), 3)]
        events = [{"id": "c", "object": "chat.completion.chunk", "choices": [{"index": 0, "delta": {"content": p}}]}
                  for p in pieces]
        args = json.dumps({"to": email, "subject": f"For {first}"})
        events += [{"id": "c", "choices": [{"index": 0, "delta": {"tool_calls": [
            {"index": 0, "id": "t1", "type": "function", "function": {"name": "send_email", "arguments": args[i:i + 5]}}
        ]}}]} for i in range(0, len(args), 5)]
        events.append({"id": "c", "choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]})
        return httpx.Response(200, text=sse(*events), headers={"content-type": "text/event-stream"})

    client, _ = client_for(Upstream(answer))
    async with client:
        r = await client.post("/v1/chat/completions",
                              json={"model": "m", "stream": True, "messages": [{"role": "user", "content": MAIL}]})
    text, args = "", ""
    for line in r.text.splitlines():
        if line.startswith("data: ") and line != "data: [DONE]":
            for c in json.loads(line[6:]).get("choices", []):
                text += c.get("delta", {}).get("content") or ""
                for tc in c.get("delta", {}).get("tool_calls") or []:
                    args += tc["function"]["arguments"]
    assert text == "Sure Dana Reyes, done."
    assert json.loads(args) == {"to": "dana.reyes@gmail.com", "subject": "For Dana"}


@pytest.mark.anyio
async def test_anthropic_stream_and_system_prompt():
    def answer(body):
        assert "Dana" not in json.dumps(body["system"])
        first, last = fake_name(body)
        events = [
            ("message_start", {"type": "message_start", "message": {"id": "m", "content": []}}),
            ("content_block_start", {"type": "content_block_start", "index": 0,
                                     "content_block": {"type": "text", "text": ""}}),
        ]
        txt = f"Writing to {first} {last} now."
        events += [("content_block_delta", {"type": "content_block_delta", "index": 0,
                                            "delta": {"type": "text_delta", "text": txt[i:i + 4]}})
                   for i in range(0, len(txt), 4)]
        events += [("content_block_stop", {"type": "content_block_stop", "index": 0}),
                   ("content_block_start", {"type": "content_block_start", "index": 1,
                                            "content_block": {"type": "tool_use", "id": "t", "name": "note",
                                                              "input": {}}})]
        js = json.dumps({"who": f"{first} {last}"})
        events += [("content_block_delta", {"type": "content_block_delta", "index": 1,
                                            "delta": {"type": "input_json_delta", "partial_json": js[i:i + 6]}})
                   for i in range(0, len(js), 6)]
        events += [("content_block_stop", {"type": "content_block_stop", "index": 1}),
                   ("message_stop", {"type": "message_stop"})]
        out = "".join(f"event: {e}\ndata: {json.dumps(d)}\n\n" for e, d in events)
        return httpx.Response(200, text=out, headers={"content-type": "text/event-stream"})

    client, _ = client_for(Upstream(answer))
    async with client:
        r = await client.post("/v1/messages", headers={"x-api-key": "k", "anthropic-version": "2023-06-01"},
                              json={"model": "m", "stream": True, "system": "You help Dana Reyes.",
                                    "messages": [{"role": "user", "content": MAIL}]})
    text, js = "", ""
    for line in r.text.splitlines():
        if line.startswith("data: "):
            d = json.loads(line[6:])
            delta = d.get("delta") or {}
            text += delta.get("text", "") if delta.get("type") == "text_delta" else ""
            js += delta.get("partial_json", "") if delta.get("type") == "input_json_delta" else ""
    assert text == "Writing to Dana Reyes now."
    assert json.loads(js) == {"who": "Dana Reyes"}


@pytest.mark.anyio
async def test_responses_api_non_stream():
    def answer(body):
        first, _ = fake_name(body)
        return httpx.Response(200, json={"output": [{"type": "message", "content": [
            {"type": "output_text", "text": f"Hello {first}"}]}]})

    up = Upstream(answer)
    client, _ = client_for(up)
    async with client:
        r = await client.post("/v1/responses", json={"model": "m", "input": MAIL})
    assert r.json()["output"][0]["content"][0]["text"] == "Hello Dana"
    assert "482913" not in up.seen[0]["raw"]


@pytest.mark.anyio
async def test_known_value_in_an_unmasked_field_is_refused():
    up = Upstream(lambda body: httpx.Response(200, json={}))
    client, _ = client_for(up)
    async with client:
        await client.post("/v1/chat/completions", headers={"x-opn-session": "s"},
                          json={"model": "m", "messages": [{"role": "user", "content": MAIL}]})
        r = await client.post("/v1/chat/completions", headers={"x-opn-session": "s"},
                              json={"model": "m", "messages": [{"role": "user", "content": "hi"}],
                                    "metadata": {"customer": "Dana Reyes"}})
    assert r.status_code == 422 and r.json()["error"]["type"] == "opn_egress_refused"
    assert "Dana" not in r.text
    assert len(up.seen) == 1  # the second request never left


@pytest.mark.anyio
async def test_profiles_can_only_be_chosen_from_the_allowed_list_and_only_tighten():
    up = Upstream(lambda body: httpx.Response(200, json={"choices": []}))
    client, _ = client_for(up, profile="schedule", allowed_profiles=("summarize",))
    async with client:
        r = await client.post("/v1/chat/completions", headers={"x-opn-profile": "secrets_only"},
                              json={"model": "m", "messages": [{"role": "user", "content": MAIL}]})
        assert r.status_code == 403
        r = await client.post("/v1/chat/completions", headers={"x-opn-profile": "summarize"},
                              json={"model": "m", "messages": [{"role": "user", "content": MAIL}]})
    assert r.status_code == 200
    assert "[EMAIL removed]" in up.seen[0]["raw"]  # summarize drops emails, stricter than schedule


@pytest.mark.anyio
async def test_handles_are_filled_only_for_configured_tools():
    def answer(body):
        calls = [{"id": "a", "type": "function", "function": {"name": "browser_type",
                                                             "arguments": '{"text":"{{OTP_1}}"}'}},
                 {"id": "b", "type": "function", "function": {"name": "send_email",
                                                             "arguments": '{"body":"{{OTP_1}}"}'}}]
        return httpx.Response(200, json={"choices": [{"index": 0, "message": {"role": "assistant",
                                                                               "tool_calls": calls}}]})

    client, _ = client_for(Upstream(answer), profile="browse_and_fill",
                           fill_tools={"browser_type": "https://login.acme.com"})
    async with client:
        r = await client.post("/v1/chat/completions", headers={"x-opn-source-sender": "no-reply@acme.com"},
                              json={"model": "m", "messages": [{"role": "user", "content": MAIL}]})
    calls = r.json()["choices"][0]["message"]["tool_calls"]
    assert json.loads(calls[0]["function"]["arguments"]) == {"text": "482913"}
    assert json.loads(calls[1]["function"]["arguments"]) == {"body": "{{OTP_1}}"}  # not configured: stays a handle


@pytest.mark.anyio
async def test_stream_without_done_still_delivers_every_word():
    def answer(body):
        first, last = fake_name(body)
        text = f"Bye {first} {last}"
        events = [{"id": "c", "choices": [{"index": 0, "delta": {"content": text[i:i + 2]}}]}
                  for i in range(0, len(text), 2)]
        return httpx.Response(200, text=sse(*events, done=False), headers={"content-type": "text/event-stream"})

    client, _ = client_for(Upstream(answer))
    async with client:
        r = await client.post("/v1/chat/completions",
                              json={"model": "m", "stream": True, "messages": [{"role": "user", "content": MAIL}]})
    text = "".join(c.get("delta", {}).get("content") or "" for line in r.text.splitlines()
                   if line.startswith("data: ") and line != "data: [DONE]"
                   for c in json.loads(line[6:]).get("choices", []))
    assert text == "Bye Dana Reyes"


@pytest.mark.anyio
async def test_string_arguments_stay_valid_json_when_real_values_have_quotes():
    s_name = 'Dana "DJ" Reyes'

    def answer(body):
        fake = json.dumps(body).split("meet ")[1].split(" today")[0].replace('\\"', '"')
        args = json.dumps({"who": fake})
        return httpx.Response(200, json={"choices": [{"index": 0, "message": {"role": "assistant", "tool_calls": [
            {"id": "a", "type": "function", "function": {"name": "note", "arguments": args}}]}}]})

    client, _ = client_for(Upstream(answer), known={"PERSON": [s_name]})
    async with client:
        r = await client.post("/v1/chat/completions",
                              json={"model": "m", "messages": [{"role": "user", "content": f"meet {s_name} today"}]})
    args = r.json()["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"]
    assert json.loads(args) == {"who": s_name}
