"""The part of a gateway that has nothing to do with HTTP: sessions and their vaults, receipt logs, masking a whole
request body and restoring an answer. The local proxy (`open_pseudonym.proxy`) and the LiteLLM guardrail
(`open_pseudonym.litellm`) are both built on it, so they mask and restore the same way.
"""

from __future__ import annotations

import hashlib
import json
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .egress import EgressLog
from .handles import HANDLE, HandleRefused, Sink, Source
from .jws import Signer
from .policy import Policy, load_profile
from .session import SKIP_KEYS, TOP_KEYS, Session
from .vault import Vault


@dataclass
class GatewayConfig:
    profile: str = "strict"
    allowed_profiles: tuple = ()  # names a caller may pick per request; always tightened with `profile`
    log_dir: str | None = None  # where receipts go; None keeps them in memory only
    signer: Signer | None = None
    store_payloads: bool = True
    vault_dir: str | None = None  # persist each session's vault here, encrypted with vault_key
    vault_key: bytes | None = None
    fill_tools: dict = field(default_factory=dict)  # tool name -> site it acts on; handles may be filled for these
    known: dict = field(default_factory=dict)
    max_sessions: int = 1000


class Gateway:
    """Holds the sessions. `config` is a GatewayConfig or anything with the same fields (the proxy's ProxyConfig)."""

    def __init__(self, config: Any):
        self.config = config
        self.base_policy = load_profile(config.profile)
        self.signer = config.signer or Signer.generate()
        self.sessions: OrderedDict[str, Session] = OrderedDict()
        self.logs: dict[str, EgressLog] = {}

    # Sessions

    def policy_named(self, name: str | None) -> Policy:
        """The policy for a profile a caller asked for: the base policy when none, tightened with it otherwise."""
        if not name:
            return self.base_policy
        if name not in self.config.allowed_profiles:
            raise PermissionError(f"profile {name!r} is not enabled on this gateway")
        return self.base_policy.tighten(load_profile(name))

    def session_for(self, sid: str, policy: Policy) -> Session:
        s = self.sessions.get(sid)
        if s is None:
            vault = None
            path = self._vault_path(sid)
            if path and path.exists():
                vault = Vault.load(path, self.config.vault_key)
            s = Session(policy, vault, known=self.config.known, session_id=sid, release_log=self.log_for(sid))
            self.sessions[sid] = s
            while len(self.sessions) > self.config.max_sessions:
                old, _ = self.sessions.popitem(last=False)
                self.logs.pop(old, None)  # its log is on disk already; a later request opens it again
        else:
            self.sessions.move_to_end(sid)
            s.policy = policy if policy.digest == s.policy.digest else s.policy.tighten(policy)
        return s

    def _vault_path(self, sid: str) -> Path | None:
        if not self.config.vault_dir or not self.config.vault_key:
            return None
        return Path(self.config.vault_dir) / f"{file_id(sid)}.vault"

    def save(self, s: Session) -> None:
        path = self._vault_path(s.id)
        if path:
            path.parent.mkdir(parents=True, exist_ok=True)
            s.vault.save(path, self.config.vault_key)

    def log_for(self, sid: str) -> EgressLog | None:
        if not self.config.log_dir:
            return None
        if sid not in self.logs:
            self.logs[sid] = EgressLog(Path(self.config.log_dir) / file_id(sid), self.signer, self.config.store_payloads)
        return self.logs[sid]

    # Request bodies

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
            out = Gateway._mask_once(s, body, source)
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

    # The answer comes from the model provider: any part may be missing or of another type. Parts that are not the
    # expected shape are left exactly as they are, never a crash halfway through a restore.

    def restore_chat(self, s: Session, data: Any) -> Any:
        for choice in _dicts(_field(data, "choices")):
            msg = choice.get("message")
            if not isinstance(msg, dict):
                continue
            if isinstance(msg.get("content"), str):
                msg["content"] = s.restore(msg["content"])
            for call in _dicts(msg.get("tool_calls")):
                fn = call.get("function")
                if isinstance(fn, dict) and isinstance(fn.get("arguments"), str):
                    fn["arguments"] = self.restore_args(s, _name(fn), fn["arguments"])
        return data

    def restore_anthropic(self, s: Session, data: Any) -> Any:
        for block in _dicts(_field(data, "content")):
            if block.get("type") == "text" and isinstance(block.get("text"), str):
                block["text"] = s.restore(block["text"])
            elif block.get("type") == "tool_use":
                block["input"] = self.restore_args(s, _name(block), block.get("input"))
        return data

    def restore_responses(self, s: Session, data: Any) -> Any:
        for item in _dicts(_field(data, "output")):
            if item.get("type") == "message":
                for part in _dicts(item.get("content")):
                    if isinstance(part.get("text"), str):
                        part["text"] = s.restore(part["text"])
            elif item.get("type") == "function_call" and isinstance(item.get("arguments"), str):
                item["arguments"] = self.restore_args(s, _name(item), item["arguments"])
        if isinstance(data, dict) and isinstance(data.get("output_text"), str):
            data["output_text"] = s.restore(data["output_text"])
        return data


def _field(data: Any, key: str) -> Any:
    return data.get(key) if isinstance(data, dict) else None


def _dicts(value: Any) -> list[dict]:
    return [v for v in value if isinstance(v, dict)] if isinstance(value, list) else []


def _name(obj: dict) -> str:
    name = obj.get("name")
    return name if isinstance(name, str) else ""


def file_id(sid: str) -> str:
    """A file-safe name for a session id that cannot collide (a.b and ab stay apart)."""
    return hashlib.sha256(sid.encode("utf-8")).hexdigest()[:32]
