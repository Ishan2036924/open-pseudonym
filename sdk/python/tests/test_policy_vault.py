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
