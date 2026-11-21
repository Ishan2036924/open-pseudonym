"""The gateway shared by the local proxy and the LiteLLM guardrail, on answers of an unexpected shape."""

import pytest

from open_pseudonym import Source
from open_pseudonym.gateway import Gateway, GatewayConfig


@pytest.fixture
def gw():
    g = Gateway(GatewayConfig(profile="strict"))
    s = g.session_for("sid", g.base_policy)
    fake = s.mask("Write to dana.reyes@gmail.com", Source(sender="a@acme.com")).text.split("to ")[1]
    return g, s, fake


@pytest.mark.parametrize("data", [
    None, [], 5, "text", {"choices": None}, {"choices": [None, 3, "x"]}, {"choices": [{"message": "hi"}]},
    {"choices": [{"message": {"tool_calls": [None, {"function": 1}, {"function": {"name": [], "arguments": "{}"}}]}}]},
    {"content": [None, {"type": "text", "text": 5}, {"type": "tool_use", "name": {}, "input": None}]},
    {"output": [None, {"type": "message", "content": [None, 1]}, {"type": "function_call", "name": 2,
                                                                  "arguments": "{}"}], "output_text": 7},
])
def test_unexpected_shapes_pass_through_unchanged(gw, data):
    """Found by fuzzing: a provider answer with null or mistyped parts crashed the restore (AttributeError,
    TypeError), so the proxy answered 500 and the guardrail failed the call. Unknown parts are now left as they are."""
    g, s, _ = gw
    for restore in (g.restore_chat, g.restore_anthropic, g.restore_responses):
        assert restore(s, data) == data


def test_well_formed_parts_next_to_broken_ones_still_restore(gw):
    g, s, fake = gw
    data = {"choices": [None, {"message": {"content": f"Mail {fake}"}}]}
    assert g.restore_chat(s, data)["choices"][1]["message"]["content"] == "Mail dana.reyes@gmail.com"
    blocks = {"content": [3, {"type": "text", "text": fake}]}
    assert g.restore_anthropic(s, blocks)["content"][1]["text"] == "dana.reyes@gmail.com"
