"""Policies: for one kind of task, what happens to each type of personal data.

A policy is a small JSON document (see spec section 5). The important property is direction: code may always make a
policy stricter, but nothing in this library lets a model's output loosen it. Each action has a strength, and
`tighten` and `with_rules` refuse to lower it.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field

from . import _data
from .jcs import canonical, digest
from .types import DIGIT_TYPES, check_type_name

# How much each action hides. "keep" hides nothing; "refuse" stops the request.
STRENGTH = {
    "keep": 0,
    "shift": 1,
    "generalize": 1,
    "fake": 2,
    "tag": 2,
    "token": 2,
    "fpe": 2,
    "handle": 3,
    "drop": 4,
    "refuse": 5,
}
ACTIONS = tuple(STRENGTH)

# Options each action understands. Anything else is a typo we would rather catch early.
_OPTIONS = {
    "fake": {"keep_gender", "keep_region"},
    "handle": {"uses", "ttl_s", "ask", "tools", "sites"},
}


class PolicyError(ValueError):
    pass


@dataclass(frozen=True)
class Rule:
    action: str
    options: dict = field(default_factory=dict)

    @property
    def strength(self) -> int:
        return STRENGTH[self.action]

    def to_dict(self) -> dict:
        return {"action": self.action, **self.options}

    @classmethod
    def from_dict(cls, type_: str, doc: dict) -> "Rule":
        if not isinstance(doc, dict) or "action" not in doc:
            raise PolicyError(f"{type_}: a rule is an object with an 'action'")
        action = doc["action"]
        if action not in STRENGTH:
            raise PolicyError(f"{type_}: unknown action {action!r}")
        if action == "shift" and type_ not in ("DATE", "*"):
            raise PolicyError(f"{type_}: only dates can be shifted")
        if action == "fpe" and type_ not in DIGIT_TYPES and type_ != "*":
            raise PolicyError(f"{type_}: format-preserving encryption is for digit types only")
        options = {k: v for k, v in doc.items() if k != "action"}
        unknown = set(options) - _OPTIONS.get(action, set())
        if unknown:
            raise PolicyError(f"{type_}: option(s) {sorted(unknown)} do not apply to {action!r}")
        return cls(action, options)


@dataclass(frozen=True)
class Policy:
    id: str
    rules: dict
    default: Rule
    description: str = ""
    allow: tuple = ()

    @classmethod
    def from_dict(cls, doc: dict) -> "Policy":
        if doc.get("type") != "policy":
            raise PolicyError("not a policy document (type must be 'policy')")
        if not isinstance(doc.get("id"), str) or not doc["id"]:
            raise PolicyError("a policy needs an id")
        rules = {}
        for type_, rule in (doc.get("rules") or {}).items():
            rules[check_type_name(type_)] = Rule.from_dict(type_, rule)
        default = Rule.from_dict("*", doc.get("default") or {"action": "tag"})
        if default.action in ("shift", "fpe"):
            raise PolicyError("the default action cannot be shift or fpe")
        allow = tuple(doc.get("allow") or ())
        return cls(doc["id"], rules, default, doc.get("description", ""), allow)

    def to_dict(self) -> dict:
        return {
            "opn": "0.1",
            "type": "policy",
            "id": self.id,
            "description": self.description,
            "rules": {t: r.to_dict() for t, r in sorted(self.rules.items())},
            "default": self.default.to_dict(),
            "allow": list(self.allow),
        }

    @property
    def digest(self) -> str:
        return digest(canonical(self.to_dict()))

    def rule_for(self, type_: str) -> Rule:
        return self.rules.get(type_, self.default)

    def tighten(self, other: "Policy") -> "Policy":
        """The stricter of two policies, type by type. Ties keep this policy's rule."""
        types = set(self.rules) | set(other.rules)
        rules = {}
        for t in types:
            mine, theirs = self.rule_for(t), other.rule_for(t)
            rules[t] = theirs if theirs.strength > mine.strength else mine
        default = other.default if other.default.strength > self.default.strength else self.default
        allow = tuple(v for v in self.allow if v in other.allow)  # only values both policies allow stay visible
        return Policy(f"{self.id}+{other.id}", rules, default, self.description, allow)

    def with_rules(self, overrides: dict) -> "Policy":
        """Apply rule overrides that may only make things stricter. Raises PolicyError on any loosening."""
        rules = dict(self.rules)
        for type_, doc in overrides.items():
            new = Rule.from_dict(check_type_name(type_), doc)
            old = self.rule_for(type_)
            if new.strength < old.strength:
                raise PolicyError(f"{type_}: {old.action!r} cannot be loosened to {new.action!r}")
            rules[type_] = new
        return Policy(self.id, rules, self.default, self.description, self.allow)


def load_profile(name: str) -> Policy:
    """One of the starter profiles shipped with the library (see `profile_names()`)."""
    return Policy.from_dict(copy.deepcopy(_data.profile_doc(name)))


def profile_names() -> list[str]:
    return _data.profile_names()


# Tool names that hint at the kind of task. Only a suggestion: the app decides.
_HINTS = [
    ("browse_and_fill", ("browser", "navigate", "click", "type_text", "fill", "login", "sign_in", "checkout")),
    ("schedule", ("calendar", "event", "meeting", "schedule", "availability", "invite")),
    ("draft_reply", ("send_email", "reply", "draft", "send_message", "compose")),
    ("money_math", ("invoice", "budget", "expense", "payment", "transaction", "ledger")),
    ("web_research", ("search", "web", "browse_url", "fetch_url", "lookup")),
    ("summarize", ("summar", "read_file", "read_document", "retrieve", "rag")),
]


def suggest_profile(tool_names: list[str]) -> str:
    """Guess a starter profile from the tools an agent has. The app should confirm; the model never chooses."""
    names = [t.lower() for t in tool_names]
    for profile, hints in _HINTS:
        if any(h in n for n in names for h in hints):
            return profile
    return "strict"
