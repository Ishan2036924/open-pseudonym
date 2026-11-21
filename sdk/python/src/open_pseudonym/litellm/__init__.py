"""Open Pseudonym as a LiteLLM proxy guardrail. See guides/litellm.md.

    # config.yaml
    guardrails:
      - guardrail_name: open-pseudonym
        litellm_params:
          guardrail: open_pseudonym.litellm.OpenPseudonymGuardrail
          mode: [pre_call, post_call]
          default_on: true
          profile: draft_reply

What happens to one request:
  1. before the model call, every field LiteLLM will send is masked (messages, system prompts, tools, Responses
     input), the same way the OPN proxy masks a body
  2. the egress check reads the masked request; a known real value, or new personal data in a field masking did not
     cover, stops the request. With `log_dir`, a signed receipt is written for what was released
  3. after routing, just before the provider call, the final request is checked again, so a value added later (by a
     deployment setting or another guardrail) also stops it
  4. the answer comes back restored, streamed or not; tool-call arguments are restored too, and secret handles are
     filled in only for tools listed in `fill_tools`, with a signed release record when `log_dir` is set

Every failure stops the request. Error messages name types, never values.
"""

from __future__ import annotations

import copy
import hashlib
import json
import logging
from importlib.metadata import PackageNotFoundError, version
from urllib.parse import urlsplit
from collections import OrderedDict
from pathlib import Path
from typing import Any

try:
    from fastapi import HTTPException
    from litellm.integrations.custom_guardrail import CustomGuardrail
    from litellm.types.utils import MCP_GUARDRAIL_CALL_TYPES, ChatCompletionDeltaToolCall, Function
except ImportError as e:  # the optional dependency is not installed
    raise ImportError('open_pseudonym.litellm needs the LiteLLM proxy: pip install "open-pseudonym[litellm]"') from e

from ..egress import EgressLeak
from ..gateway import Gateway, GatewayConfig
from ..handles import Source
from ..jws import Signer
from ..session import RefusedData, Session

TESTED = "1.108."  # the LiteLLM line these hooks were read and tested against
try:
    if not version("litellm").startswith(TESTED):
        logging.getLogger(__name__).warning("open_pseudonym.litellm was tested with LiteLLM %sx, found %s; run its tests "
                                            "before relying on it", TESTED, version("litellm"))
except PackageNotFoundError:  # a source checkout of LiteLLM: nothing to compare
    pass

# Fields LiteLLM keeps for itself: routing, auth, logging and bookkeeping. They are not sent to the model, so they are
# not masked (masking them would break LiteLLM), and they are not part of what the egress check reads.
INTERNAL = frozenset({
    "metadata", "proxy_server_request", "secret_fields", "guardrails", "guardrail_to_apply", "model_info",
    "api_key", "api_base", "api_version", "base_url", "organization", "client", "shared_session", "caching", "cache",
    "timeout", "request_timeout", "max_retries", "num_retries", "mock_response", "mock_tool_calls", "deployment",
    "use_in_pass_through", "allow_client_keepalive_override", "merge_reasoning_content_in_choices", "headers",
    "extra_headers", "incoming_bearer_token", "custom_llm_provider", "model_list", "fallbacks", "context_window_fallbacks",
    "input_cost_per_token", "output_cost_per_token", "aws_access_key_id", "aws_secret_access_key", "vertex_credentials",
})
INTERNAL_PREFIXES = ("litellm_", "_", "user_api_key_", "mcp_")
# The call types this guardrail masks, checks and restores. Every other call type that reaches it is refused (fail
# closed): pass-through routes, batches, files, audio, images and the rest carry content we do not mask or cannot
# restore. An operator who wants one of them anyway lists it in `skip_call_types`, which lets it through unprotected.
HANDLED = frozenset({"completion", "acompletion", "text_completion", "atext_completion", "responses", "aresponses",
                     "anthropic_messages", "embedding", "aembedding"})
# MCP tool calls and tool listings run through the same hook; they are not model input, so they are left alone.
NOT_MODEL_INPUT = frozenset(MCP_GUARDRAIL_CALL_TYPES)
_HEADER_SESSION, _HEADER_PROFILE = "x-opn-session", "x-opn-profile"
_HEADER_SENDER, _HEADER_SITE = "x-opn-source-sender", "x-opn-source-site"


def _internal(key: str) -> bool:
    return key in INTERNAL or key.startswith(INTERNAL_PREFIXES)


def _plain(value: Any) -> Any:
    """JSON-ready form of what LiteLLM may hold: pydantic objects become dicts; anything else unknown becomes text, so
    the egress check reads it rather than skipping it."""
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, dict):
        return {str(k): _plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(v) for v in value]
    dump = getattr(value, "model_dump", None)
    if callable(dump):
        return _plain(dump())
    return str(value)


def outgoing(data: dict) -> dict:
    """The part of a LiteLLM request that goes to the model."""
    return {k: v for k, v in data.items() if not _internal(k)}


def _refuse(status: int, kind: str, message: str, **extra: Any) -> HTTPException:
    return HTTPException(status_code=status, detail={"error": {"type": kind, "message": message, **extra}})


def _headers(data: dict) -> dict:
    meta = data.get("metadata") or data.get("litellm_metadata") or {}
    headers = meta.get("headers") if isinstance(meta, dict) else None
    return {str(k).lower(): v for k, v in headers.items()} if isinstance(headers, dict) else {}


def _owner(user: Any) -> str:
    """Who is calling, from LiteLLM's own key check, never from the body. Two callers never share a vault even when
    they send the same session id."""
    parts = [str(getattr(user, name, None) or "") for name in ("api_key", "token", "user_id", "team_id", "end_user_id")]
    return hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()[:24]


def _dest(kwargs: dict) -> str:
    """Where this attempt goes: the deployment's host, else its provider and model."""
    base = kwargs.get("api_base") or kwargs.get("base_url")
    if isinstance(base, str) and base:
        return urlsplit(base).hostname or base
    return f"{kwargs.get('custom_llm_provider') or 'litellm'}:{kwargs.get('model') or ''}"


def _copy(obj: Any) -> Any:
    """A private copy to restore into. LiteLLM keeps the objects it hands us (the stream cache is built from the same
    chunks), so real values must never be written into them: a cached answer would carry them to the next caller."""
    if hasattr(obj, "model_copy"):
        return obj.model_copy(deep=True)
    return copy.deepcopy(obj)


def _get(obj: Any, name: str) -> Any:
    return obj.get(name) if isinstance(obj, dict) else getattr(obj, name, None)


def _set(obj: Any, name: str, value: Any) -> None:
    if isinstance(obj, dict):
        obj[name] = value
    else:
        setattr(obj, name, value)


class OpenPseudonymGuardrail(CustomGuardrail):
    def __init__(
        self,
        *,
        profile: str = "strict",
        allowed_profiles: list[str] | tuple[str, ...] = (),
        key_dir: str | None = None,
        log_dir: str | None = None,
        vault_dir: str | None = None,
        store_payloads: bool = True,
        fill_tools: dict[str, str] | None = None,
        known: dict[str, list[str]] | None = None,
        max_sessions: int = 1000,
        skip_call_types: list[str] | tuple[str, ...] = (),
        signer: Signer | None = None,
        vault_key: bytes | None = None,
        **kwargs: Any,
    ) -> None:
        """key_dir is a folder made by `opn keygen`: `signing.pem` signs receipts and release records, `vault.key`
        encrypts vaults kept in vault_dir. Keys are read from files, never from config.yaml."""
        if key_dir:
            folder = Path(key_dir).expanduser()
            if signer is None and (folder / "signing.pem").exists():
                signer = Signer.from_pem((folder / "signing.pem").read_bytes())
            if vault_key is None and (folder / "vault.key").exists():
                vault_key = (folder / "vault.key").read_bytes()
        if vault_dir and (vault_key is None or len(vault_key) != 32):
            raise ValueError("vault_dir needs a 32-byte vault.key in key_dir (run `opn keygen`)")
        if log_dir and signer is None:
            raise ValueError("log_dir needs a signing key: put signing.pem in key_dir (run `opn keygen`)")
        self.gateway = Gateway(GatewayConfig(
            profile=profile, allowed_profiles=tuple(allowed_profiles), log_dir=log_dir, signer=signer,
            store_payloads=store_payloads, vault_dir=vault_dir, vault_key=vault_key, fill_tools=dict(fill_tools or {}),
            known=dict(known or {}), max_sessions=max_sessions))
        self.skip_call_types = NOT_MODEL_INPUT | set(skip_call_types)
        self.handled = HANDLED - self.skip_call_types
        self.calls: OrderedDict[str, str] = OrderedDict()  # LiteLLM call id -> session id, for the answer
        self.receipts: OrderedDict[str, list[str]] = OrderedDict()  # LiteLLM call id -> one receipt per attempt
        super().__init__(**kwargs)

    # Which session a call belongs to

    def _remember(self, table: OrderedDict, call_id: str, value: str) -> None:
        table[call_id] = value
        table.move_to_end(call_id)
        while len(table) > self.gateway.config.max_sessions * 4:
            table.popitem(last=False)

    def _session_of(self, data: Any) -> Session | None:
        call_id = _get(data, "litellm_call_id") if data is not None else None
        sid = self.calls.get(call_id) if call_id else None
        return self.gateway.sessions.get(sid) if sid else None

    # Before the model call

    async def async_pre_call_hook(self, user_api_key_dict: Any, cache: Any, data: dict, call_type: Any) -> dict:
        kind = getattr(call_type, "value", call_type)
        if kind in self.skip_call_types:
            return data
        if kind not in self.handled:
            raise _refuse(400, "opn_unsupported_call", f"{kind} requests are not protected by this gateway")
        headers = _headers(data)
        try:
            policy = self.gateway.policy_named(headers.get(_HEADER_PROFILE))
        except PermissionError:
            raise _refuse(403, "opn_profile_refused", "that profile is not enabled on this gateway") from None
        call_id = str(data.get("litellm_call_id") or "")
        sid = f"{_owner(user_api_key_dict)}:{headers.get(_HEADER_SESSION) or call_id or id(data)}"
        s = self.gateway.session_for(sid, policy)
        sender, site = headers.get(_HEADER_SENDER), headers.get(_HEADER_SITE)
        source = Source(sender=sender, site=site) if sender or site else None
        try:
            masked = self.gateway.mask_body(s, outgoing(data), source)
            payload = json.dumps(_plain(masked), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            leaks = s.check_egress(payload)
            if leaks:
                raise EgressLeak(leaks)
        except RefusedData as exc:
            raise _refuse(400, "opn_refused", str(exc)) from None
        except EgressLeak as exc:
            raise _refuse(400, "opn_egress_refused", str(exc), types=sorted({lk.type for lk in exc.leaks})) from None
        except (UnicodeError, RecursionError, TypeError, ValueError):  # unprocessable: refuse, never forward
            raise _refuse(400, "opn_bad_request", "request cannot be processed") from None
        data.update(masked)
        self.gateway.save(s)
        if call_id:
            self._remember(self.calls, call_id, sid)
        return data

    async def async_pre_call_deployment_hook(self, kwargs: dict, call_type: Any) -> dict | None:
        """After routing, right before the provider call: the last point that can still stop it. Checks the final
        request again, so a real value added after our pre-call masking (a deployment's settings, another guardrail,
        a fallback) never leaves."""
        out = await super().async_pre_call_deployment_hook(kwargs, call_type)
        final = out if isinstance(out, dict) else kwargs
        s = self._session_of(final)
        if s is None:
            return out
        try:
            payload = json.dumps(_plain(outgoing(final)), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            log = self.gateway.log_for(s.id)
            if log is None:
                leaks = s.check_egress(payload)
                if leaks:
                    raise EgressLeak(leaks)
            else:  # one signed receipt per attempt, naming where this attempt goes (a retry or fallback gets its own)
                receipt = s.record_egress(log, payload, _dest(final))
                call_id = str(final.get("litellm_call_id"))
                self._remember(self.receipts, call_id, [*self.receipts.get(call_id, []), receipt])
        except EgressLeak as exc:
            raise _refuse(400, "opn_egress_refused", str(exc), types=sorted({lk.type for lk in exc.leaks})) from None
        except (UnicodeError, RecursionError, TypeError, ValueError):
            raise _refuse(400, "opn_bad_request", "request cannot be processed") from None
        return out

    # After the model call

    async def async_post_call_success_hook(self, data: dict, user_api_key_dict: Any, response: Any) -> Any:
        s = self._session_of(data)
        if s is None or response is None:
            return response
        response = _copy(response)
        if isinstance(response, dict):
            if "choices" in response:
                self.gateway.restore_chat(s, response)
            elif "output" in response:
                self.gateway.restore_responses(s, response)
            elif isinstance(response.get("content"), list):
                self.gateway.restore_anthropic(s, response)
        elif _get(response, "choices") is not None:
            self._restore_choices(s, response)
        elif _get(response, "output") is not None:
            self._restore_output(s, response)
        elif isinstance(_get(response, "content"), list):
            self._restore_blocks(s, response)
        self.gateway.save(s)
        return response

    def _restore_choices(self, s: Session, response: Any) -> None:
        for choice in _get(response, "choices") or []:
            msg = _get(choice, "message")
            if msg is None:
                continue
            if isinstance(_get(msg, "content"), str):
                _set(msg, "content", s.restore(_get(msg, "content")))
            for call in _get(msg, "tool_calls") or []:
                fn = _get(call, "function")
                if fn is not None and isinstance(_get(fn, "arguments"), str):
                    _set(fn, "arguments", self.gateway.restore_args(s, _get(fn, "name") or "", _get(fn, "arguments")))

    def _restore_output(self, s: Session, response: Any) -> None:
        for item in _get(response, "output") or []:
            if _get(item, "type") == "message":
                for part in _get(item, "content") or []:
                    if isinstance(_get(part, "text"), str):
                        _set(part, "text", s.restore(_get(part, "text")))
            elif _get(item, "type") == "function_call" and isinstance(_get(item, "arguments"), str):
                _set(item, "arguments", self.gateway.restore_args(s, _get(item, "name") or "", _get(item, "arguments")))

    def _restore_blocks(self, s: Session, response: Any) -> None:
        for block in _get(response, "content") or []:
            if _get(block, "type") == "text" and isinstance(_get(block, "text"), str):
                _set(block, "text", s.restore(_get(block, "text")))
            elif _get(block, "type") == "tool_use":
                _set(block, "input", self.gateway.restore_args(s, _get(block, "name") or "", _get(block, "input")))

    async def async_post_call_streaming_iterator_hook(self, user_api_key_dict: Any, response: Any, request_data: dict):
        """Text is restored as it streams; a stand-in split across chunks is held back until it is whole. Tool-call
        arguments are held until their choice finishes, then restored in one piece (a half argument cannot be)."""
        s = self._session_of(request_data)
        if s is None:
            async for chunk in response:
                yield chunk
            return
        texts: dict[int, Any] = {}
        calls: dict[tuple[int, int], dict] = {}
        last = None
        async for original in response:
            chunk = _copy(original)
            last = chunk
            for choice in _get(chunk, "choices") or []:
                idx = _get(choice, "index") or 0
                delta = _get(choice, "delta")
                if delta is None:
                    continue
                if isinstance(_get(delta, "content"), str) and _get(delta, "content"):
                    st = texts.setdefault(idx, s.stream())
                    _set(delta, "content", st.feed(_get(delta, "content")))
                for tc in _get(delta, "tool_calls") or []:
                    key = (idx, _get(tc, "index") or 0)
                    call = calls.setdefault(key, {"id": None, "name": "", "arguments": ""})
                    call["id"] = _get(tc, "id") or call["id"]
                    fn = _get(tc, "function")
                    call["name"] = (_get(fn, "name") if fn is not None else None) or call["name"]
                    call["arguments"] += (_get(fn, "arguments") if fn is not None else None) or ""
                if _get(delta, "tool_calls"):
                    _set(delta, "tool_calls", None)
                if _get(choice, "finish_reason"):
                    self._flush(s, idx, delta, texts, calls)
            yield chunk
        # a stream that ended without a finish_reason: never drop what was held back
        held = sorted(set(texts) | {k[0] for k in calls})
        if held and last is not None:
            tail = last.model_copy(deep=True) if hasattr(last, "model_copy") else json.loads(json.dumps(last))
            choices = []
            for idx in held:
                template = (_get(tail, "choices") or [None])[0]
                if template is None:
                    break
                choice = template.model_copy(deep=True) if hasattr(template, "model_copy") else dict(template)
                _set(choice, "index", idx)
                delta = _get(choice, "delta")
                _set(delta, "content", None)
                _set(delta, "tool_calls", None)
                self._flush(s, idx, delta, texts, calls)
                choices.append(choice)
            if choices:
                _set(tail, "choices", choices)
                yield tail
        self.gateway.save(s)

    def _flush(self, s: Session, idx: int, delta: Any, texts: dict, calls: dict) -> None:
        st = texts.pop(idx, None)
        rest = st.flush() if st else ""
        if rest:
            _set(delta, "content", (_get(delta, "content") or "") + rest)
        mine = sorted(k for k in calls if k[0] == idx)
        if mine:
            out = []
            for key in mine:
                call = calls.pop(key)
                args = self.gateway.restore_args(s, call["name"], call["arguments"])
                out.append(ChatCompletionDeltaToolCall(id=call["id"], type="function", index=key[1],
                                                       function=Function(name=call["name"], arguments=args)))
            _set(delta, "tool_calls", out)
