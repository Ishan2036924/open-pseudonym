"""The official OpenAI and Anthropic Python SDKs, unchanged, with the proxy as their HTTP transport."""

import json

import httpx
import pytest

openai = pytest.importorskip("openai")
anthropic = pytest.importorskip("anthropic")

from open_pseudonym.proxy import ProxyConfig, async_transport  # noqa: E402

MAIL = "From: Dana Reyes <dana.reyes@gmail.com>\nHi Sam, call (617) 555-0142."


def upstream(seen):
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        raw = request.content.decode()
        seen.append(raw)
        fake = raw.split("From: ")[1].split(" <")[0]
        if request.url.path.endswith("/messages"):
            return httpx.Response(200, json={"id": "m", "type": "message", "role": "assistant", "model": "x",
                                             "content": [{"type": "text", "text": f"Replying to {fake}."}],
                                             "stop_reason": "end_turn", "usage": {"input_tokens": 1, "output_tokens": 1}})
        return httpx.Response(200, json={"id": "c", "object": "chat.completion", "created": 0, "model": body["model"],
                                         "choices": [{"index": 0, "finish_reason": "stop", "message": {
                                             "role": "assistant", "content": f"Replying to {fake}."}}]})
    return handler


@pytest.mark.anyio
async def test_openai_sdk():
    seen = []
    t = async_transport(ProxyConfig(profile="draft_reply", transport=httpx.MockTransport(upstream(seen))))
    client = openai.AsyncOpenAI(api_key="test", http_client=httpx.AsyncClient(transport=t))
    r = await client.chat.completions.create(model="m", messages=[{"role": "user", "content": MAIL}])
    assert r.choices[0].message.content == "Replying to Dana Reyes."
    assert "Dana" not in seen[0] and "(617) 555-0142" not in seen[0]


@pytest.mark.anyio
async def test_anthropic_sdk():
    seen = []
    httpx2 = pytest.importorskip("httpx2")
    t = async_transport(ProxyConfig(profile="draft_reply", transport=httpx.MockTransport(upstream(seen))),
                        library="httpx2")
    client = anthropic.AsyncAnthropic(api_key="test", http_client=httpx2.AsyncClient(transport=t))
    r = await client.messages.create(model="m", max_tokens=50, messages=[{"role": "user", "content": MAIL}])
    assert r.content[0].text == "Replying to Dana Reyes."
    assert "Dana" not in seen[0]
