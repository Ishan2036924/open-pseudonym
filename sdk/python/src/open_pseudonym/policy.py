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


def _is_suffix(host: str) -> bool:
    from .fakes import is_public_suffix

    return is_public_suffix(host)


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
        for site in options.get("sites") or []:
            # *.com or *.github.io would let anyone's site match; a wildcard needs a real domain under it
            if isinstance(site, str) and site.startswith("*.") and ("." not in site[2:] or _is_suffix(site[2:])):
                raise PolicyError(f"{type_}: {site!r} covers a whole public suffix")
        unknown = set(options) - _OPTIONS.get(action, set())
        if unknown:
            raise PolicyError(f"{type_}: option(s) {sorted(unknown)} do not apply to {action!r}")
        return cls(action, options)


def _min_opt(a, b):
    """The smaller of two optional limits; None means no limit."""
    if a is None:
        return b
    if b is None:
        return a
    return min(a, b)


def _narrow(a, b):
    """Two optional allow-lists combined so the result allows only what both allow. None when neither is set,
    an empty list when they have nothing in common."""
    if not a:
        return list(b) if b else None
    if not b:
        return list(a)
    return [x for x in a if x in b]


def stricter(a: Rule, b: Rule) -> Rule:
    """The stricter of two rules. When both are the same action, their limits combine, so tightening can never
    drop a handle's `uses`, `ttl_s`, `ask`, `sites` or `tools`. Ties between different actions keep `a`."""
    if a.strength != b.strength:
        return a if a.strength > b.strength else b
    if a.action != b.action or a.action != "handle":
        return a
    opts = {}
    uses = _min_opt(a.options.get("uses"), b.options.get("uses"))
    ttl = _min_opt(a.options.get("ttl_s"), b.options.get("ttl_s"))
    sites = _narrow(a.options.get("sites"), b.options.get("sites"))
    tools = _narrow(a.options.get("tools"), b.options.get("tools"))
    if sites == [] or tools == []:
        return Rule("drop")  # the two sides allow no common place, so nothing may ever be filled
    if uses is not None:
        opts["uses"] = uses
    if ttl is not None:
        opts["ttl_s"] = ttl
    if a.options.get("ask") or b.options.get("ask"):
        opts["ask"] = True
    if sites is not None:
        opts["sites"] = sites
    if tools is not None:
        opts["tools"] = tools
    return Rule("handle", opts)


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
            rules[t] = stricter(self.rule_for(t), other.rule_for(t))
        default = stricter(self.default, other.default)
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
            rules[type_] = stricter(new, old)  # same action: the old limits still apply
        return Policy(self.id, rules, self.default, self.description, self.allow)


# A simple switch for products: how much the person wants hidden. Secrets (codes, passwords, cards, bank numbers,
# SSNs, keys) are hidden at every level, as handles the model can still use, so nothing breaks for the task.
LEVELS = {
    1: ("secrets_only", "Secrets", "Codes, passwords, cards, bank numbers and keys are hidden. Everything else is visible."),
    2: ("contacts", "Contacts", "Secrets, plus emails, phone numbers, street addresses and IPs. Names stay visible."),
    3: ("strict", "Everything", "Secrets, contacts, names, companies and places are replaced; dates shift together."),
}


def load_level(level: int) -> Policy:
    """The policy behind a privacy level (1, 2 or 3). A product can show LEVELS[n][1] and [2] as the label and
    the one-line explanation, and let the person choose."""
    if level not in LEVELS:
        raise PolicyError(f"levels are 1, 2 and 3, got {level!r}")
    return load_profile(LEVELS[level][0])


def load_profile(name: str) -> Policy:
    """One of the starter profiles shipped with the library (see `profile_names()`)."""
    return Policy.from_dict(copy.deepcopy(_data.profile_doc(name)))


def policy_for(profile: str, level: int | None = None) -> Policy:
    """One call for the two choices: the task's profile, made stricter by the person's level when one is given.
    `policy_for("schedule", 3)` keeps the real dates scheduling needs, unless the level hides more."""
    policy = load_profile(profile)
    return policy if level is None else policy.tighten(load_level(level))


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
