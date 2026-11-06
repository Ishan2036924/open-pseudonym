"""A local proxy that speaks the providers' own APIs, so any app gets protection by changing one base URL.

    opn proxy --profile draft_reply --port 8787
    # then point the app at http://127.0.0.1:8787/v1 (OpenAI style) or http://127.0.0.1:8787 (Anthropic style)

What happens to one request:
  1. the body is masked (messages, system prompt, Responses API input), with handle notes added
  2. the exact bytes are checked for known real values and a signed receipt is written; a leak stops the request
  3. the request goes upstream with the app's own credentials, untouched
  4. the answer comes back restored, streamed or not; tool-call arguments are restored too, and secret handles are
     filled in only for tools the proxy was told about and only where their binding allows

The vault for each session lives in this process (and optionally on disk, encrypted). It never goes upstream.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route

from ..egress import EgressLeak, EgressLog
from ..handles import HANDLE, HandleRefused, Sink, Source
from ..jws import Signer
from ..policy import Policy, load_profile
from ..session import SKIP_KEYS, TOP_KEYS, RefusedData, Session
from ..vault import Vault
from .sse import Event, Parser

# headers that must not be copied from the app's request to the upstream, or back
HOP = {"host", "content-length", "connection", "keep-alive", "transfer-encoding", "te", "trailer", "upgrade",
       "proxy-authorization", "proxy-connection", "accept-encoding", "content-encoding"}


@dataclass
class ProxyConfig:
    profile: str = "strict"
    allowed_profiles: tuple = ()  # names an app may pick with x-opn-profile; always tightened with `profile`
    openai_upstream: str = "https://api.openai.com"
    anthropic_upstream: str = "https://api.anthropic.com"
    log_dir: str | None = None  # where receipts go; None keeps them in memory only
    signer: Signer | None = None
    store_payloads: bool = True
    vault_dir: str | None = None  # persist each session's vault here, encrypted with vault_key
    vault_key: bytes | None = None
    fill_tools: dict = field(default_factory=dict)  # tool name -> site it acts on; handles may be filled for these
    known: dict = field(default_factory=dict)
    max_sessions: int = 1000
    transport: Any = None  # an httpx transport, for tests
    timeout_s: float = 600.0


class Proxy:
    def __init__(self, config: ProxyConfig):
        self.config = config
        self.base_policy = load_profile(config.profile)
        self.signer = config.signer or Signer.generate()
        self.sessions: OrderedDict[str, Session] = OrderedDict()
        self.logs: dict[str, EgressLog] = {}
        self.client = httpx.AsyncClient(transport=config.transport, timeout=config.timeout_s)

    # Sessions

    def policy_for(self, request: Request) -> Policy:
        name = request.headers.get("x-opn-profile")
        if not name:
            return self.base_policy
        if name not in self.config.allowed_profiles:
            raise PermissionError(f"profile {name!r} is not enabled on this proxy")
        return self.base_policy.tighten(load_profile(name))

    def session_for(self, sid: str, policy: Policy) -> Session:
        s = self.sessions.get(sid)
        if s is None:
            vault = None
            path = self._vault_path(sid)
            if path and path.exists():
                vault = Vault.load(path, self.config.vault_key)
            s = Session(policy, vault, known=self.config.known, session_id=sid)
            self.sessions[sid] = s
            while len(self.sessions) > self.config.max_sessions:
                self.sessions.popitem(last=False)
        else:
            self.sessions.move_to_end(sid)
            s.policy = policy if policy.digest == s.policy.digest else s.policy.tighten(policy)
        return s

    def _vault_path(self, sid: str) -> Path | None:
        if not self.config.vault_dir or not self.config.vault_key:
            return None
        return Path(self.config.vault_dir) / f"{_file_id(sid)}.vault"

    def save(self, s: Session) -> None:
        path = self._vault_path(s.id)
        if path:
            path.parent.mkdir(parents=True, exist_ok=True)
            s.vault.save(path, self.config.vault_key)

    def log_for(self, sid: str) -> EgressLog | None:
        if not self.config.log_dir:
            return None
        if sid not in self.logs:
            self.logs[sid] = EgressLog(Path(self.config.log_dir) / _file_id(sid), self.signer, self.config.store_payloads)
        return self.logs[sid]

    # Request bodies

    @staticmethod
    def source_for(request: Request) -> Source | None:
        sender = request.headers.get("x-opn-source-sender")
        site = request.headers.get("x-opn-source-site")
        return Source(sender=sender, site=site) if sender or site else None

    @staticmethod
    def mask_body(s: Session, body: dict, source: Source | None) -> dict:
        """Mask the whole request body. Chat histories go through mask_messages so handle notes land in the message
        that mentions them; every other field (system prompts, documents, names, metadata, tool descriptions) is
        masked too, leaving only structural keys and base64 blobs alone.

        Two passes: a name learned late in the body (in a message) may also appear earlier (in the system prompt)
        without any cue, so the second pass, with everything learned, catches it. Stand-ins do not change between
        passes because they come from the vault."""
        out = body
        for _ in range(2):
            out = Proxy._mask_once(s, body, source)
        return out

    @staticmethod
    def _mask_once(s: Session, body: dict, source: Source | None) -> dict:
        out = {}
        for key, value in body.items():
            if key in SKIP_KEYS or key in TOP_KEYS:
                out[key] = value  # structure such as the model name; the egress check still reads it
            elif key in ("messages", "input") and isinstance(value, list):
                out[key], _ = s.mask_messages(value, source)
            elif key == "input" and isinstance(value, str):
                m = s.mask(value, source)
                out[key] = m.text + ("\n\n" + "\n".join("Note: " + n for n in m.notes) if m.notes else "")
            elif key in ("system", "instructions") and isinstance(value, str):
                m = s.mask(value, source)
                out[key] = m.text + ("\n\n" + "\n".join("Note: " + n for n in m.notes) if m.notes else "")
            else:
                out[key], _ = s.mask_value(value, source)
        return out

    # Restoring

    def restore_args(self, s: Session, tool: str, args: Any) -> Any:
        """Tool-call arguments on their way back to the app.

        Fakes always turn back into real values. Handles are filled in only for tools listed in `fill_tools`, and
        only if the binding allows that tool's site; otherwise they stay as {{handles}} for the app to resolve.
        JSON strings are parsed first, so a real value with a quote in it cannot break the JSON.
        """
        if isinstance(args, str):
            try:
                parsed = json.loads(args)
            except ValueError:
                return s.restore_keep_handles(args)
            return json.dumps(self.restore_args(s, tool, parsed), ensure_ascii=False)
        if HANDLE.search(json.dumps(args)) and tool in self.config.fill_tools:
            try:
                return s.resolve_args(args, Sink(tool=tool, site=self.config.fill_tools[tool])).args
            except HandleRefused:
                pass
        return s.restore_keep_handles(args)

    def restore_chat(self, s: Session, data: dict) -> dict:
        for choice in data.get("choices") or []:
            msg = choice.get("message") or {}
            if isinstance(msg.get("content"), str):
                msg["content"] = s.restore(msg["content"])
            for call in msg.get("tool_calls") or []:
                fn = call.get("function") or {}
                if isinstance(fn.get("arguments"), str):
                    fn["arguments"] = self.restore_args(s, fn.get("name", ""), fn["arguments"])
        return data

    def restore_anthropic(self, s: Session, data: dict) -> dict:
        for block in data.get("content") or []:
            if block.get("type") == "text":
                block["text"] = s.restore(block["text"])
            elif block.get("type") == "tool_use":
                block["input"] = self.restore_args(s, block.get("name", ""), block.get("input"))
        return data

    def restore_responses(self, s: Session, data: dict) -> dict:
        for item in data.get("output") or []:
            if item.get("type") == "message":
                for part in item.get("content") or []:
                    if isinstance(part.get("text"), str):
                        part["text"] = s.restore(part["text"])
            elif item.get("type") == "function_call" and isinstance(item.get("arguments"), str):
                item["arguments"] = self.restore_args(s, item.get("name", ""), item["arguments"])
        if isinstance(data.get("output_text"), str):
            data["output_text"] = s.restore(data["output_text"])
        return data

    # Streams

    async def stream_chat(self, s: Session, upstream: httpx.Response):
        parser = Parser()
        texts: dict[int, Any] = {}
        calls: dict[tuple[int, int], dict] = {}

        def flush_choice(idx: int):
            out = []
            st = texts.pop(idx, None)
            rest = st.flush() if st else ""
            if rest:
                out.append({"index": idx, "delta": {"content": rest}})
            for (ci, ti), call in sorted(calls.items()):
                if ci != idx:
                    continue
                args = self.restore_args(s, call["name"], call["arguments"])
                out.append({"index": idx, "delta": {"tool_calls": [
                    {"index": ti, "id": call["id"], "type": "function",
                     "function": {"name": call["name"], "arguments": args}}]}})
            for key in [k for k in calls if k[0] == idx]:
                del calls[key]
            return out

        template: dict = {}
        async for chunk in upstream.aiter_bytes():
            for ev in parser.feed(chunk):
                if ev.data.strip() == "[DONE]":
                    for idx in list(texts) + sorted({k[0] for k in calls}):
                        for c in flush_choice(idx):
                            yield Event(json.dumps({**template, "choices": [c]})).encode()
                    yield ev.encode()
                    continue
                try:
                    data = json.loads(ev.data)
                except ValueError:
                    yield ev.encode()
                    continue
                template = {k: v for k, v in data.items() if k in ("id", "object", "created", "model")}
                out_choices = []
                for choice in data.get("choices") or []:
                    idx = choice.get("index", 0)
                    delta = choice.get("delta") or {}
                    if isinstance(delta.get("content"), str):
                        st = texts.setdefault(idx, s.stream())
                        delta["content"] = st.feed(delta["content"])
                    for tc in delta.pop("tool_calls", None) or []:
                        key = (idx, tc.get("index", 0))
                        call = calls.setdefault(key, {"id": None, "name": "", "arguments": ""})
                        call["id"] = tc.get("id") or call["id"]
                        fn = tc.get("function") or {}
                        call["name"] = fn.get("name") or call["name"]
                        call["arguments"] += fn.get("arguments") or ""
                    if choice.get("finish_reason"):
                        for c in flush_choice(idx):
                            yield Event(json.dumps({**template, "choices": [c]})).encode()
                    out_choices.append(choice)
                if out_choices or not data.get("choices"):
                    data["choices"] = out_choices
                    yield Event(json.dumps(data)).encode()
        for ev in parser.close():
            yield ev.encode()
        # some servers end the stream without [DONE] or a finish_reason; never drop what we were holding back
        for idx in sorted(set(texts) | {k[0] for k in calls}):
            for c in flush_choice(idx):
                yield Event(json.dumps({**template, "choices": [c]})).encode()

    async def stream_anthropic(self, s: Session, upstream: httpx.Response):
        parser = Parser()
        texts: dict[int, Any] = {}
        tools: dict[int, dict] = {}
        async for chunk in upstream.aiter_bytes():
            for ev in parser.feed(chunk):
                try:
                    data = json.loads(ev.data)
                except ValueError:
                    yield ev.encode()
                    continue
                kind = data.get("type")
                idx = data.get("index", 0)
                if kind == "content_block_start":
                    block = data.get("content_block") or {}
                    if block.get("type") == "text":
                        texts[idx] = s.stream()
                        block["text"] = s.restore(block.get("text", ""))
                    elif block.get("type") == "tool_use":
                        tools[idx] = {"name": block.get("name", ""), "json": ""}
                elif kind == "content_block_delta":
                    delta = data.get("delta") or {}
                    if delta.get("type") == "text_delta" and idx in texts:
                        delta["text"] = texts[idx].feed(delta.get("text", ""))
                        if not delta["text"]:
                            continue
                    elif delta.get("type") == "input_json_delta" and idx in tools:
                        tools[idx]["json"] += delta.get("partial_json", "")
                        continue
                elif kind == "content_block_stop":
                    if idx in texts:
                        rest = texts.pop(idx).flush()
                        if rest:
                            extra = {"type": "content_block_delta", "index": idx,
                                     "delta": {"type": "text_delta", "text": rest}}
                            yield Event(json.dumps(extra), "content_block_delta").encode()
                    if idx in tools:
                        t = tools.pop(idx)
                        try:
                            restored = json.dumps(self.restore_args(s, t["name"], json.loads(t["json"] or "{}")))
                        except ValueError:
                            restored = s.restore_keep_handles(t["json"])
                        extra = {"type": "content_block_delta", "index": idx,
                                 "delta": {"type": "input_json_delta", "partial_json": restored}}
                        yield Event(json.dumps(extra), "content_block_delta").encode()
                yield Event(json.dumps(data), ev.event).encode()
        for ev in parser.close():
            yield ev.encode()

    async def stream_responses(self, s: Session, upstream: httpx.Response):
        parser = Parser()
        texts: dict[tuple, Any] = {}
        args: dict[str, str] = {}
        names: dict[str, str] = {}
        async for chunk in upstream.aiter_bytes():
            for ev in parser.feed(chunk):
                try:
                    data = json.loads(ev.data)
                except ValueError:
                    yield ev.encode()
                    continue
                kind = data.get("type", ev.event)
                key = (data.get("item_id"), data.get("content_index"))
                if kind == "response.output_text.delta":
                    st = texts.setdefault(key, s.stream())
                    data["delta"] = st.feed(data.get("delta", ""))
                    if not data["delta"]:
                        continue
                elif kind == "response.output_text.done":
                    st = texts.pop(key, None)
                    rest = st.flush() if st else ""
                    if rest:
                        extra = {**data, "type": "response.output_text.delta", "delta": rest}
                        extra.pop("text", None)
                        yield Event(json.dumps(extra), "response.output_text.delta").encode()
                    data["text"] = s.restore(data.get("text", ""))
                elif kind == "response.output_item.added" and (data.get("item") or {}).get("type") == "function_call":
                    names[data["item"].get("id")] = data["item"].get("name", "")
                elif kind == "response.function_call_arguments.delta":
                    args[data.get("item_id")] = args.get(data.get("item_id"), "") + data.get("delta", "")
                    continue
                elif kind == "response.function_call_arguments.done":
                    item_id = data.get("item_id")
                    full = args.pop(item_id, data.get("arguments", ""))
                    restored = self.restore_args(s, names.get(item_id, ""), full)
                    extra = {"type": "response.function_call_arguments.delta", "item_id": item_id,
                             "output_index": data.get("output_index"), "delta": restored}
                    yield Event(json.dumps(extra), "response.function_call_arguments.delta").encode()
                    data["arguments"] = restored
                elif isinstance(data.get("response"), dict):
                    self.restore_responses(s, data["response"])
                elif isinstance(data.get("item"), dict):
                    self.restore_responses(s, {"output": [data["item"]]})
                yield Event(json.dumps(data), ev.event).encode()
        for ev in parser.close():
            yield ev.encode()

    # The endpoint

    async def handle(self, request: Request, kind: str) -> Response:
        try:
            body = await request.json()
        except (ValueError, RecursionError):
            return JSONResponse({"error": {"type": "opn_bad_request", "message": "body must be JSON"}}, 400)
        if not isinstance(body, dict):
            return JSONResponse({"error": {"type": "opn_bad_request", "message": "body must be a JSON object"}}, 400)
        try:
            policy = self.policy_for(request)
        except PermissionError as exc:
            return JSONResponse({"error": {"type": "opn_profile_refused", "message": str(exc)}}, 403)
        sid = request.headers.get("x-opn-session") or uuid.uuid4().hex
        s = self.session_for(sid, policy)
        try:
            masked = self.mask_body(s, body, self.source_for(request))
            payload = json.dumps(masked, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        except RefusedData as exc:
            return JSONResponse({"error": {"type": "opn_refused", "message": str(exc)}}, 422)
        except (UnicodeError, RecursionError):  # lone surrogates, absurd nesting: refuse, never crash
            return JSONResponse({"error": {"type": "opn_bad_request", "message": "body cannot be processed"}}, 400)
        upstream_base = self.config.anthropic_upstream if kind == "anthropic" else self.config.openai_upstream
        url = upstream_base.rstrip("/") + request.url.path
        receipt = None
        log = self.log_for(sid)
        try:
            if request.url.query:
                # the query string goes upstream too, so it gets the same check first (headers are not checked:
                # they carry credentials and API versions, and the app sets them, not the model)
                query_leaks = s.check_egress(json.dumps(dict(request.query_params)))
                if query_leaks:
                    raise EgressLeak(query_leaks)
            if log is not None:
                receipt = s.record_egress(log, payload, httpx.URL(url).host)
            else:
                leaks = s.check_egress(payload)
                if leaks:
                    raise EgressLeak(leaks)
        except EgressLeak as exc:
            types = sorted({lk.type for lk in exc.leaks})
            return JSONResponse({"error": {"type": "opn_egress_refused", "message": str(exc), "types": types}}, 422)
        self.save(s)
        headers = {k: v for k, v in request.headers.items() if k.lower() not in HOP and not k.lower().startswith("x-opn-")}
        headers["content-type"] = "application/json"
        out_headers = {"x-opn-session": sid}
        if receipt:
            out_headers["x-opn-receipt"] = receipt
        streaming = bool(body.get("stream"))
        req = self.client.build_request(request.method, url, headers=headers, content=payload,
                                        params=dict(request.query_params))
        upstream = await self.client.send(req, stream=True)
        if upstream.status_code >= 400 or not streaming:
            raw = await upstream.aread()
            await upstream.aclose()
            try:
                data = json.loads(raw)
            except ValueError:
                return Response(raw, upstream.status_code, media_type=upstream.headers.get("content-type"))
            if upstream.status_code < 400:
                data = {"chat": self.restore_chat, "anthropic": self.restore_anthropic,
                        "responses": self.restore_responses}[kind](s, data)
                unknown = s.unknown_stand_ins(json.dumps(data))
                if unknown:
                    out_headers["x-opn-unknown"] = ",".join(unknown)[:2000]
            self.save(s)
            return JSONResponse(data, upstream.status_code, headers=out_headers)
        gen = {"chat": self.stream_chat, "anthropic": self.stream_anthropic, "responses": self.stream_responses}[kind]

        async def body_iter():
            try:
                async for piece in gen(s, upstream):
                    yield piece
            finally:
                await upstream.aclose()
                self.save(s)

        return StreamingResponse(body_iter(), upstream.status_code, headers=out_headers,
                                 media_type="text/event-stream")


def create_app(config: ProxyConfig | None = None) -> Starlette:
    proxy = Proxy(config or ProxyConfig())

    async def chat(request: Request):
        return await proxy.handle(request, "chat")

    async def anthropic(request: Request):
        return await proxy.handle(request, "anthropic")

    async def responses(request: Request):
        return await proxy.handle(request, "responses")

    async def health(request: Request):
        return JSONResponse({"ok": True, "profile": proxy.config.profile, "sessions": len(proxy.sessions),
                             "key_id": proxy.signer.kid, "time": int(time.time())})

    app = Starlette(routes=[
        Route("/v1/chat/completions", chat, methods=["POST"]),
        Route("/v1/messages", anthropic, methods=["POST"]),
        Route("/v1/responses", responses, methods=["POST"]),
        Route("/health", health, methods=["GET"]),
    ])
    app.state.proxy = proxy
    return app


def _file_id(sid: str) -> str:
    """A file-safe name for a session id that cannot collide (a.b and ab stay apart)."""
    return hashlib.sha256(sid.encode("utf-8")).hexdigest()[:32]


def default_key_dir() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return Path(base) / "open-pseudonym"


def async_transport(config: ProxyConfig | None = None, *, library: str = "httpx", **kw) -> Any:
    """The proxy as an in-process transport, for async SDK clients that accept a custom http_client.

        from openai import AsyncOpenAI
        client = AsyncOpenAI(http_client=httpx.AsyncClient(transport=async_transport(profile="draft_reply")))

        from anthropic import AsyncAnthropic   # Anthropic's SDK 2.x is built on httpx2
        client = AsyncAnthropic(http_client=httpx2.AsyncClient(transport=async_transport(library="httpx2")))

    Requests never touch the network on their way to the proxy; the proxy then forwards to the real provider.
    """
    if config is None:
        config = ProxyConfig(**kw)
    if library == "httpx2":
        import httpx2

        return httpx2.ASGITransport(app=create_app(config))
    return httpx.ASGITransport(app=create_app(config))
