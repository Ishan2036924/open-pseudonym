"""Policies only get stricter; vaults round-trip and stay locked."""

import os
import stat

import pytest

from open_pseudonym import Policy, PolicyError, Session, Vault, VaultError, load_profile, profile_names
from open_pseudonym.policy import suggest_profile


def test_every_profile_loads():
    assert len(profile_names()) >= 10
    for name in profile_names():
        assert load_profile(name).id == name


def test_cannot_loosen():
    p = load_profile("strict")
    with pytest.raises(PolicyError, match="cannot be loosened"):
        p.with_rules({"OTP": {"action": "keep"}})
    assert p.with_rules({"PERSON": {"action": "drop"}}).rule_for("PERSON").action == "drop"


def test_tighten_takes_the_stricter_rule():
    a, b = load_profile("schedule"), load_profile("summarize")
    t = a.tighten(b)
    assert t.rule_for("EMAIL").action == "drop"  # summarize drops, schedule fakes
    assert t.rule_for("OTP").action == "drop"  # handle (3) < drop (4)
    assert t.rule_for("DATE").action == "shift"  # keep (0) < shift (1)


@pytest.mark.parametrize("rules,msg", [
    ({"PERSON": {"action": "shift"}}, "only dates can be shifted"),
    ({"EMAIL": {"action": "fpe"}}, "digit types only"),
    ({"PERSON": {"action": "fake", "colour": "red"}}, "do not apply"),
    ({"PERSON": {"action": "vanish"}}, "unknown action"),
    ({"person": {"action": "fake"}}, "upper case"),
])
def test_bad_policies_fail_early(rules, msg):
    with pytest.raises(ValueError, match=msg):
        Policy.from_dict({"opn": "0.1", "type": "policy", "id": "x", "rules": rules})


def test_policy_digest_is_stable():
    assert load_profile("strict").digest == load_profile("strict").digest
    assert load_profile("strict").digest != load_profile("schedule").digest


def test_suggestions_are_advice_only():
    assert suggest_profile(["create_calendar_event"]) == "schedule"
    assert suggest_profile(["browser_navigate", "browser_type"]) == "browse_and_fill"
    assert suggest_profile(["unknown_thing"]) == "strict"


def test_vault_save_load(tmp_path):
    s = Session("strict", Vault(seed=bytes(32)))
    masked = s.mask("Hi Dana Reyes,\nmail dana@acme.com").text
    key = os.urandom(32)
    path = tmp_path / "v.opn"
    s.vault.save(path, key)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert b"Dana" not in path.read_bytes()
    s2 = Session("strict", Vault.load(path, key))
    assert s2.restore(masked) == "Hi Dana Reyes,\nmail dana@acme.com"
    assert s2.mask("Dana Reyes again").text == s.mask("Dana Reyes again").text
    with pytest.raises(VaultError):
        Vault.load(path, os.urandom(32))


def test_tightening_keeps_every_handle_limit():
    """Critic finding: same-strength overrides used to drop uses, ttl and ask."""
    p = load_profile("strict").with_rules({"OTP": {"action": "handle"}, "SSN": {"action": "handle"}})
    assert p.rule_for("OTP").options == {"uses": 1, "ttl_s": 600}
    assert p.rule_for("SSN").options == {"ask": True}
    a = Policy.from_dict({"opn": "0.1", "type": "policy", "id": "a",
                          "rules": {"PASSWORD": {"action": "handle", "uses": 1, "sites": ["acme.com"], "ask": True}}})
    b = Policy.from_dict({"opn": "0.1", "type": "policy", "id": "b",
                          "rules": {"PASSWORD": {"action": "handle", "uses": 5, "sites": ["acme.com", "x.example"]}}})
    for t in (a.tighten(b), b.tighten(a)):
        assert t.rule_for("PASSWORD").options == {"uses": 1, "ask": True, "sites": ["acme.com"]}
    c = Policy.from_dict({"opn": "0.1", "type": "policy", "id": "c",
                          "rules": {"PASSWORD": {"action": "handle", "sites": ["other.example"]}}})
    assert a.tighten(c).rule_for("PASSWORD").action == "drop"  # no site both allow: nothing may be filled


def test_levels_always_hide_secrets_and_add_more_as_they_go_up():
    from open_pseudonym import LEVELS, load_level
    from open_pseudonym.types import SECRET_TYPES

    hidden = []
    for n in sorted(LEVELS):
        p = load_level(n)
        assert all(p.rule_for(t).action == "handle" for t in SECRET_TYPES), n  # secrets hidden at every level
        hidden.append({t for t in ("PERSON", "EMAIL", "PHONE", "ADDRESS", "ORG") if p.rule_for(t).action != "keep"})
    assert hidden[0] == set() and hidden[1] == {"EMAIL", "PHONE", "ADDRESS"} and hidden[2] >= hidden[1] | {"PERSON"}
    with pytest.raises(PolicyError):
        load_level(4)


def test_a_wildcard_over_a_public_suffix_is_refused():
    for site in ["*.com", "*.github.io", "*.co.uk"]:
        with pytest.raises(PolicyError, match="public suffix"):
            Policy.from_dict({"opn": "0.1", "type": "policy", "id": "x",
                              "rules": {"OTP": {"action": "handle", "sites": [site]}}})
