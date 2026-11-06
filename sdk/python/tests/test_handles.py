"""Secret handles: filled in only where they belong, and never half filled."""

import pytest

from open_pseudonym import HandleRefused, Sink, Source

OTP_MAIL = "Your Acme verification code is 482913. It expires in 10 minutes."


def otp_session(make_session, **kw):
    s = make_session("browse_and_fill", **kw)
    m = s.mask(OTP_MAIL, Source(sender="no-reply@mail.acme.com"))
    assert "{{OTP_1}}" in m.text and "482913" not in m.text
    return s, m


def test_note_tells_the_model_enough(make_session):
    _, m = otp_session(make_session)
    assert m.notes == [
        "{{OTP_1}} is a 6-digit one-time code from acme.com, valid until 00:10 UTC. Write {{OTP_1}} exactly "
        "where the value is needed; the real value is filled in outside the model."
    ]


def test_fills_on_the_bound_site_and_subdomains(make_session):
    s, _ = otp_session(make_session)
    r = s.resolve_args({"selector": "#code", "text": "{{OTP_1}}"}, Sink("type", "https://login.acme.com/2fa"))
    assert r.args == {"selector": "#code", "text": "482913"}


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
