"""Secret handles: filled in only where they belong, and never half filled."""

import pytest

from open_pseudonym import HandleRefused, Sink, Source

OTP_MAIL = "Your Acme verification code is 482913. It expires in 10 minutes."


def otp_session(make_session, **kw):
    s = make_session("browse_and_fill", **kw)
    m = s.mask(OTP_MAIL, Source(sender="no-reply@acme.com"))
    assert "{{OTP_1}}" in m.text and "482913" not in m.text
    return s, m


def test_note_tells_the_model_enough(make_session):
    _, m = otp_session(make_session)
    assert m.notes == [
        "{{OTP_1}} is a 6-digit one-time code from acme.com, valid until 00:10 UTC. Write {{OTP_1}} exactly "
        "where the value is needed; the real value is filled in outside the model."
    ]


def test_fills_on_the_exact_host_only(make_session):
    s, _ = otp_session(make_session)
    with pytest.raises(HandleRefused, match="bound to a different site"):
        s.resolve_args({"text": "{{OTP_1}}"}, Sink("type", "https://login.acme.com/2fa"))  # a subdomain is not the host
    r = s.resolve_args({"selector": "#code", "text": "{{OTP_1}}"}, Sink("type", "https://acme.com/2fa"))
    assert r.args == {"selector": "#code", "text": "482913"}


def test_a_policy_can_allow_subdomains_on_purpose(make_session):
    """Critic finding: a code from accounts.example.com used to fill on any *.example.com page."""
    from open_pseudonym import Policy

    p = Policy.from_dict({"opn": "0.1", "type": "policy", "id": "x",
                          "rules": {"OTP": {"action": "handle", "uses": 1, "sites": ["*.acme.com"]}}})
    s = make_session(p)
    s.mask("Your code is 482913")
    assert s.resolve_args({"t": "{{OTP_1}}"}, Sink("type", "https://login.acme.com")).args == {"t": "482913"}


@pytest.mark.parametrize("site", ["https://acme.com.evil.example/", "https://notacme.com", "evil.example", None])
def test_refuses_other_sites(make_session, site):
    s, _ = otp_session(make_session)
    with pytest.raises(HandleRefused) as e:
        s.resolve_args({"text": "{{OTP_1}}"}, Sink("type", site))
    assert e.value.reason == "bound to a different site"


def test_single_use_and_expiry(make_session):
    now = [1793836800]
    s, _ = otp_session(make_session, clock=lambda: now[0])
    s.resolve_args({"t": "{{OTP_1}}"}, Sink("type", "acme.com"))
    with pytest.raises(HandleRefused, match="already used"):
        s.resolve_args({"t": "{{OTP_1}}"}, Sink("type", "acme.com"))
    s2, _ = otp_session(make_session, clock=lambda: now[0])
    now[0] += 601
    with pytest.raises(HandleRefused, match="expired"):
        s2.resolve_args({"t": "{{OTP_1}}"}, Sink("type", "acme.com"))


def test_one_bad_handle_means_nothing_is_filled(make_session):
    s = make_session("browse_and_fill")
    s.mask("password: Tr0ub4dor&3", Source(site="https://acme.com"))
    s.mask("Your code is 482913", Source(sender="x@other.example"))
    with pytest.raises(HandleRefused):
        s.resolve_args({"a": "{{PASSWORD_1}}", "b": "{{OTP_1}}"}, Sink("type", "acme.com"))
    entry = s.vault.by_id(s.restorer().handles["{{OTP_1}}"])
    assert entry.meta["uses_left"] == 1  # untouched


def test_tools_ask_and_approval(make_session):
    s = make_session("browse_and_fill")
    s.policy = s.policy.with_rules({"SSN": {"action": "handle", "ask": True, "tools": ["fill_form"]}})
    s.mask("SSN 123-45-6789")
    with pytest.raises(HandleRefused, match="not allowed for this tool"):
        s.resolve_args({"v": "{{SSN_1}}"}, Sink("send_email"))
    with pytest.raises(HandleRefused, match="needs the person's approval"):
        s.resolve_args({"v": "{{SSN_1}}"}, Sink("fill_form"))
    asked = []
    s.approve = lambda h, desc, sink: asked.append((h, desc)) or True
    assert s.resolve_args({"v": "{{SSN_1}}"}, Sink("fill_form")).args == {"v": "123-45-6789"}
    assert asked == [("{{SSN_1}}", "a social security number")]


def test_unknown_handle_is_refused(make_session):
    s = make_session()
    with pytest.raises(HandleRefused, match="unknown handle"):
        s.resolve_args({"v": "{{OTP_9}}"}, Sink("type", "acme.com"))


def test_args_report_values_the_model_wrote_itself(make_session):
    s = make_session()
    m = s.mask("Hi Dana,\nmail dana@acme.com")
    fake_email = m.text.split("mail ")[1]
    r = s.resolve_args({"to": fake_email, "cc": "attacker@evil.example"}, Sink("send_email"))
    assert r.args["to"] == "dana@acme.com"
    assert {"path": "cc", "origin": "model", "types": ["EMAIL"]} in r.report


def test_json_string_arguments(make_session):
    s, _ = otp_session(make_session)
    r = s.resolve_args('{"text": "{{OTP_1}}"}', Sink("type", "acme.com"))
    assert r.args == '{"text":"482913"}'


def test_an_unbound_handle_is_never_filled(make_session):
    """Critic finding: with no source, a password used to fill anywhere, any number of times."""
    s = make_session("browse_and_fill")
    s.mask("password: Hunter2!xyz and card 4111 1111 1111 1111")
    for args in ({"b": "{{PASSWORD_1}}"}, {"b": "{{CARD_1}}"}):
        with pytest.raises(HandleRefused, match="not bound to a site or tool"):
            s.resolve_args(args, Sink("send_email", "https://evil.example"))


def test_text_cannot_stretch_a_codes_lifetime(make_session):
    now = [1793836800]
    s = make_session("browse_and_fill", clock=lambda: now[0])
    s.mask("Your code is 482913. It is valid for 999 hours.", Source(sender="x@acme.com"))
    now[0] += 601  # past the profile's 600 seconds, far inside the 999 hours the text claims
    with pytest.raises(HandleRefused, match="expired"):
        s.resolve_args({"t": "{{OTP_1}}"}, Sink("type", "acme.com"))


def test_text_alone_is_capped_at_an_hour(make_session):
    from open_pseudonym import Policy

    p = Policy.from_dict({"opn": "0.1", "type": "policy", "id": "x", "rules": {"OTP": {"action": "handle"}}})
    now = [1793836800]
    s = make_session(p, clock=lambda: now[0])
    s.mask("Your code is 482913, valid for 30 hours.", Source(sender="x@acme.com"))
    now[0] += 3601
    with pytest.raises(HandleRefused, match="expired"):
        s.resolve_args({"t": "{{OTP_1}}"}, Sink("type", "acme.com"))


def test_shared_hosting_and_backslash_tricks_are_refused(make_session):
    """Critic findings: acme.github.io filled on attacker.github.io; evil.example\\@acme.com read as acme.com."""
    s = make_session("browse_and_fill")
    s.mask("Your code is 482913", Source(sender="no-reply@acme.github.io"))
    for site in ["https://attacker.github.io/login", "https://evil.example\\@acme.github.io/"]:
        with pytest.raises(HandleRefused, match="bound to a different site"):
            s.resolve_args({"t": "{{OTP_1}}"}, Sink("type", site))
    assert s.resolve_args({"t": "{{OTP_1}}"}, Sink("type", "https://acme.github.io/2fa")).args == {"t": "482913"}


def test_short_codes_are_hidden_again_when_history_is_resent(make_session):
    """Critic finding: a filled 4-digit code came back in the next request's history as is."""
    s = make_session("browse_and_fill")
    s.mask("Enter 4821 to verify", Source(sender="x@acme.com"))
    s.resolve_args({"t": "{{OTP_1}}"}, Sink("type", "acme.com"))
    msgs, _ = s.mask_messages([{"role": "tool", "content": "typed 4821 into the box"}])
    assert "4821" not in msgs[0]["content"]


def test_zero_expiry_and_bare_shared_hosts(make_session):
    """Found while porting: 'expires in 0 minutes' used to mean never, and noreply@github.io bound all of github.io."""
    s = make_session("browse_and_fill")
    s.mask("Your code is 482913, it expires in 0 minutes", Source(sender="x@acme.com"))
    with pytest.raises(HandleRefused, match="expired"):
        s.resolve_args({"t": "{{OTP_1}}"}, Sink("type", "acme.com"))
    t = make_session("browse_and_fill", seed=b"\x01" * 32)
    t.mask("Your code is 482913", Source(sender="noreply@github.io"))
    with pytest.raises(HandleRefused, match="not bound"):
        t.resolve_args({"t": "{{OTP_1}}"}, Sink("type", "https://anyone.github.io"))
