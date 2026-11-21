"""End to end: the real LiteLLM proxy, configured from a config.yaml, with the guardrail in front of a fake model that
records the exact bytes it received. No real model is called."""

import json
import os
import re
import socket
import threading
import time

import pytest

pytest.importorskip("litellm.proxy.proxy_server")

import uvicorn  # noqa: E402
from starlette.applications import Starlette  # noqa: E402
from starlette.responses import JSONResponse, Response  # noqa: E402
from starlette.routing import Route  # noqa: E402
from starlette.testclient import TestClient  # noqa: E402

from open_pseudonym import Signer, verify_log  # noqa: E402

MAIL = "From: Dana Reyes <dana.reyes@gmail.com>\nHi Sam,\nCall (617) 555-0142. Your Acme verification code is 482913."
REAL = ["Dana", "Reyes", "dana.reyes", "(617) 555-0142", "482913"]
MASTER = "sk-test-master-key"


class FakeModel:
    """An OpenAI-style model on a local port. It records every body and answers with `answer(body)`."""

    def __init__(self):
        self.seen: list[bytes] = []
        self.answer = None
        self.port = _free_port()

        async def chat(request):
            raw = await request.body()
            self.seen.append(raw)
            out = self.answer(json.loads(raw))
            if isinstance(out, str):
                return Response(out, media_type="text/event-stream")
            return JSONResponse(out)

        app = Starlette(routes=[Route("/v1/chat/completions", chat, methods=["POST"]),
                                Route("/v1/responses", chat, methods=["POST"]),
                                Route("/v1/embeddings", chat, methods=["POST"])])
        self.server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=self.port, log_level="error"))
        threading.Thread(target=self.server.run, daemon=True).start()
        for _ in range(100):
            if self.server.started:
                break
            time.sleep(0.05)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def fake_name(body):
    return re.search(r"From: ([A-Z][a-z]+) ([A-Z][a-z]+) <", json.dumps(body)).groups()


def chunk(delta, finish=None):
    return "data: " + json.dumps({"id": "c1", "object": "chat.completion.chunk", "created": 1, "model": "fake-model",
                                  "choices": [{"index": 0, "delta": delta, "finish_reason": finish}]}) + "\n\n"


@pytest.fixture(scope="module")
def proxy(tmp_path_factory):
    folder = tmp_path_factory.mktemp("litellm")
    keys = folder / "keys"
    keys.mkdir()
    signer = Signer.from_seed(bytes(32))
    (keys / "signing.pem").write_bytes(signer.to_pem())
    model = FakeModel()
    config = folder / "config.yaml"
    config.write_text(f"""
model_list:
  - model_name: fake
    litellm_params:
      model: openai/fake-model
      api_base: http://127.0.0.1:{model.port}/v1
      api_key: test-not-a-real-key
guardrails:
  - guardrail_name: open-pseudonym
    litellm_params:
      guardrail: open_pseudonym.litellm.OpenPseudonymGuardrail
      mode: [pre_call, post_call]
      default_on: true
      profile: browse_and_fill
      key_dir: {keys}
      log_dir: {folder / "log"}
      fill_tools:
        browser_type: https://acme.com/login
router_settings:
  disable_cooldowns: true
general_settings:
  master_key: {MASTER}
""")
    old = {k: os.environ.get(k) for k in ("CONFIG_FILE_PATH", "LITELLM_TELEMETRY")}
    os.environ["CONFIG_FILE_PATH"] = str(config)
    os.environ["LITELLM_TELEMETRY"] = "False"
    from litellm.proxy.proxy_server import app

    with TestClient(app) as client:
        yield client, model, signer, folder
    for k, v in old.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    model.server.should_exit = True


def post(client, body, **headers):
    return client.post("/v1/chat/completions", json={"model": "fake", **body},
                       headers={"Authorization": f"Bearer {MASTER}", **headers})


def test_what_reaches_the_model_is_masked_and_the_reply_is_restored(proxy):
    client, model, _, _ = proxy
    model.seen.clear()

    def answer(body):
        first, last = fake_name(body)
        return {"id": "c1", "object": "chat.completion", "created": 1, "model": "fake-model",
                "choices": [{"index": 0, "finish_reason": "stop",
                             "message": {"role": "assistant", "content": f"Hi {first}, I will call {first} {last}."}}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}}

    model.answer = answer
    r = post(client, {"messages": [{"role": "system", "content": "Be brief."}, {"role": "user", "content": MAIL}]})
    assert r.status_code == 200, r.text
    assert r.json()["choices"][0]["message"]["content"] == "Hi Dana, I will call Dana Reyes."
    (raw,) = model.seen
    for value in REAL:
        assert value.encode() not in raw  # the exact bytes the model got


def test_a_stream_is_restored_across_chunk_edges(proxy):
    client, model, _, _ = proxy
    model.seen.clear()

    def answer(body):
        first, last = fake_name(body)
        text = f"Sure {first} {last}, done."
        return "".join(chunk({"content": text[i:i + 3]}) for i in range(0, len(text), 3)) + chunk({}, "stop") + \
            "data: [DONE]\n\n"

    model.answer = answer
    text = ""
    with client.stream("POST", "/v1/chat/completions", headers={"Authorization": f"Bearer {MASTER}"},
                       json={"model": "fake", "stream": True, "messages": [{"role": "user", "content": MAIL}]}) as r:
        assert r.status_code == 200
        for line in r.iter_lines():
            if line.startswith("data: ") and line != "data: [DONE]":
                for c in json.loads(line[6:]).get("choices", []):
                    text += (c.get("delta") or {}).get("content") or ""
    assert text == "Sure Dana Reyes, done."
    for value in REAL:
        assert value.encode() not in model.seen[0]


def test_a_handle_is_filled_only_for_the_listed_tool_and_everything_is_signed(proxy):
    client, model, signer, folder = proxy
    model.seen.clear()

    def answer(body):
        assert "{{OTP_1}}" in json.dumps(body)  # the model sees a handle, never the code
        calls = [{"id": "a", "type": "function", "function": {"name": "browser_type", "arguments": '{"text":"{{OTP_1}}"}'}},
                 {"id": "b", "type": "function", "function": {"name": "send_email", "arguments": '{"body":"{{OTP_1}}"}'}}]
        return {"id": "c1", "object": "chat.completion", "created": 1, "model": "fake-model",
                "choices": [{"index": 0, "finish_reason": "tool_calls",
                             "message": {"role": "assistant", "content": None, "tool_calls": calls}}]}

    model.answer = answer
    r = post(client, {"messages": [{"role": "user", "content": MAIL}]}, **{"x-opn-source-sender": "no-reply@acme.com",
                                                                          "x-opn-session": "e2e-handles"})
    assert r.status_code == 200, r.text
    calls = r.json()["choices"][0]["message"]["tool_calls"]
    assert json.loads(calls[0]["function"]["arguments"]) == {"text": "482913"}
    assert json.loads(calls[1]["function"]["arguments"]) == {"body": "{{OTP_1}}"}
    logs = [p for p in (folder / "log").iterdir() if p.is_dir()]
    reports = [verify_log(p, signer.public_key) for p in logs]
    assert all(rep["problems"] == [] for rep in reports)
    assert sum(rep["releases"] for rep in reports) == 1
    for p in logs:
        assert "482913" not in (p / "receipts.jsonl").read_text()


def test_new_personal_data_masking_cannot_place_is_stopped_before_the_model(proxy):
    client, model, _, _ = proxy
    model.seen.clear()
    model.answer = lambda body: pytest.fail("the model must not be called")
    # a known value hidden under a structural key: masking leaves "id"-like keys alone, the egress check does not
    r = post(client, {"messages": [{"role": "user", "content": MAIL, "name": "x"},
                                   {"role": "tool", "tool_call_id": "dana.reyes@gmail.com", "content": "ok"}]})
    assert r.status_code == 400, r.text
    assert "opn_egress_refused" in r.text and "dana.reyes" not in r.text
    assert model.seen == []


def _plain_answer(body):
    return {"id": "c1", "object": "chat.completion", "created": 1, "model": "fake-model",
            "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": "ok"}}]}


def test_planted_defect_masking_off_the_live_proxy_still_refuses(proxy, monkeypatch):
    from open_pseudonym.gateway import Gateway

    client, model, _, _ = proxy
    model.seen.clear()
    model.answer = _plain_answer
    monkeypatch.setattr(Gateway, "mask_body", staticmethod(lambda s, body, source: body))  # plant: no masking
    r = post(client, {"messages": [{"role": "user", "content": MAIL}]})
    assert r.status_code == 400 and model.seen == []  # the egress check stops it


def test_planted_defect_masking_and_check_off_the_leak_is_seen_at_the_model(proxy, monkeypatch):
    from open_pseudonym.gateway import Gateway
    from open_pseudonym.session import Session

    client, model, _, _ = proxy
    model.seen.clear()
    model.answer = _plain_answer
    monkeypatch.setattr(Gateway, "mask_body", staticmethod(lambda s, body, source: body))
    monkeypatch.setattr(Session, "check_egress", lambda self, payload: [])
    r = post(client, {"messages": [{"role": "user", "content": MAIL}]})
    assert r.status_code == 200
    assert b"dana.reyes@gmail.com" in model.seen[0]  # so the byte checks above would catch a real leak


def _receipts(folder, signer):
    from open_pseudonym.jws import verify

    out = []
    for p in (folder / "log").iterdir():
        if not (p / "receipts.jsonl").exists():  # a session whose only request was refused
            continue
        for token in (p / "receipts.jsonl").read_text().splitlines():
            try:
                out.append(verify(token, signer.public_key, "opn-egress+jws"))
            except Exception:  # a release record, not an egress receipt
                continue
    return out


def test_responses_api_is_masked_restored_and_receipted(proxy):
    client, model, signer, folder = proxy
    model.seen.clear()

    def answer(body):
        first, last = fake_name(body)
        return {"id": "r1", "object": "response", "created_at": 1, "model": "fake-model", "status": "completed",
                "output": [{"type": "message", "id": "m1", "role": "assistant", "status": "completed",
                            "content": [{"type": "output_text", "text": f"Noted, {first} {last}.", "annotations": []}]}],
                "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2}}

    model.answer = answer
    before = len(_receipts(folder, signer))
    r = client.post("/v1/responses", headers={"Authorization": f"Bearer {MASTER}"},
                    json={"model": "fake", "input": MAIL, "instructions": "Reply to Dana Reyes."})
    assert r.status_code == 200, r.text
    assert "Noted, Dana Reyes." in r.text
    for value in REAL:
        assert value.encode() not in model.seen[0]
    after = _receipts(folder, signer)
    assert len(after) == before + 1 and after[-1]["dest"] == "127.0.0.1"


def test_anthropic_messages_route_is_masked_and_restored(proxy):
    client, model, _, _ = proxy
    model.seen.clear()

    def answer(body):  # LiteLLM sends /v1/messages for an OpenAI-style deployment over the Responses API
        first, last = fake_name(body)
        return {"id": "r1", "object": "response", "created_at": 1, "model": "fake-model", "status": "completed",
                "output": [{"type": "message", "id": "m1", "role": "assistant", "status": "completed",
                            "content": [{"type": "output_text", "text": f"Hello {first} {last}", "annotations": []}]}],
                "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2}}

    model.answer = answer
    r = client.post("/v1/messages", headers={"Authorization": f"Bearer {MASTER}"},
                    json={"model": "fake", "max_tokens": 50, "messages": [{"role": "user", "content": MAIL}]})
    assert r.status_code == 200, r.text
    assert "Hello Dana Reyes" in r.text
    for value in REAL:
        assert value.encode() not in model.seen[0]


def test_embeddings_are_masked_before_they_leave(proxy):
    client, model, _, _ = proxy
    model.seen.clear()
    model.answer = lambda body: {"object": "list", "model": "fake-model",
                                 "data": [{"object": "embedding", "index": 0, "embedding": [0.1, 0.2]}],
                                 "usage": {"prompt_tokens": 1, "total_tokens": 1}}
    r = client.post("/v1/embeddings", headers={"Authorization": f"Bearer {MASTER}"},
                    json={"model": "fake", "input": [MAIL]})
    assert r.status_code == 200, r.text
    for value in REAL:
        assert value.encode() not in model.seen[0]


def test_chat_receipt_names_the_deployment_it_went_to(proxy):
    client, model, signer, folder = proxy
    model.answer = _plain_answer
    before = len(_receipts(folder, signer))
    assert post(client, {"messages": [{"role": "user", "content": MAIL}]}).status_code == 200
    after = _receipts(folder, signer)
    assert len(after) == before + 1 and after[-1]["dest"] == "127.0.0.1"
