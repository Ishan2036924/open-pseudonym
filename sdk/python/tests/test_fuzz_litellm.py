"""Property-based fuzzing of the LiteLLM guardrail: hostile request bodies and headers, and answers of any shape.

Before the call, the only way out besides a masked request is a refusal (HTTPException, which LiteLLM answers as
4xx); nothing unmasked is ever forwarded. After the call, any answer is handed back, restored where it has the shape we
know, never a crash. Seeded; OPN_FUZZ_EXAMPLES sets the budget, as in test_fuzz.py.
"""

import asyncio
import json
import os

import pytest

pytest.importorskip("hypothesis")
pytest.importorskip("litellm.proxy.proxy_server")

from fastapi import HTTPException  # noqa: E402
from hypothesis import HealthCheck, given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from open_pseudonym.litellm import OpenPseudonymGuardrail, outgoing  # noqa: E402

EXAMPLES = int(os.environ.get("OPN_FUZZ_EXAMPLES", "60"))
FUZZ = settings(max_examples=EXAMPLES, derandomize=True, deadline=None, database=None,
                suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large])
REAL = "dana.reyes@gmail.com"
text = st.one_of(st.text(max_size=60), st.sampled_from([f"From: Dana Reyes <{REAL}>", "code 482913", "{{OTP_1}}"]))
values = st.recursive(st.one_of(st.none(), st.booleans(), st.integers(), st.floats(allow_nan=False), text),
                      lambda c: st.one_of(st.lists(c, max_size=4), st.dictionaries(text, c, max_size=4)),
                      max_leaves=16)
headers = st.dictionaries(st.sampled_from(["x-opn-session", "x-opn-profile", "x-opn-source-sender",
                                           "x-opn-source-site", "X-OPN-PROFILE", "other"]),
                          st.one_of(text, st.dictionaries(text, text, max_size=2), st.lists(text, max_size=2), values),
                          max_size=4)


class User:
    api_key, token, user_id, team_id, end_user_id = "hashed-key", None, "user-a", None, None


def guard():
    return OpenPseudonymGuardrail(guardrail_name="opn", event_hook=["pre_call", "post_call"], default_on=True,
                                  profile="strict", allowed_profiles=["draft_reply"])


@FUZZ
@given(body=st.dictionaries(st.sampled_from(["model", "messages", "input", "system", "tools", "user", "x"]), values,
                            max_size=5),
       hdrs=st.one_of(headers, values), call_type=st.sampled_from(["acompletion", "completion", "aresponses",
                                                                   "anthropic_messages", "aembedding", "x"]))
def test_pre_call_masks_or_refuses(body, hdrs, call_type):
    g = guard()
    data = {**body, "litellm_call_id": "c1", "metadata": {"headers": hdrs}}
    try:
        out = asyncio.run(g.async_pre_call_hook(User(), None, data, call_type))
    except HTTPException as exc:
        assert 400 <= exc.status_code < 500
        return
    if call_type in ("acompletion", "completion", "aresponses", "anthropic_messages"):
        assert REAL not in json.dumps(outgoing(out), default=str)


@FUZZ
@given(response=values, shape=st.sampled_from(["choices", "output", "content", "raw"]))
def test_post_call_hands_back_any_answer(response, shape):
    g = guard()
    data = {"model": "m", "messages": [{"role": "user", "content": f"From: Dana Reyes <{REAL}>"}],
            "litellm_call_id": "c1", "metadata": {"headers": {}}}
    asyncio.run(g.async_pre_call_hook(User(), None, data, "acompletion"))
    answer = response if shape == "raw" else {shape: response}
    out = asyncio.run(g.async_post_call_success_hook(data, User(), answer))
    if not isinstance(answer, dict):
        assert out == answer
