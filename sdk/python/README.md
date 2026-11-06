# open-pseudonym (Python)

Keep personal data away from AI models without making them worse at the task. Task-aware stand-ins, local restore,
secret handles that are filled in outside the model, and signed receipts for every request that leaves.

```bash
pip install open-pseudonym              # core, needs only cryptography
pip install "open-pseudonym[proxy]"     # local proxy for OpenAI and Anthropic style APIs
pip install "open-pseudonym[mcp]"       # MCP middleware and gateway
pip install "open-pseudonym[browser]"   # Playwright handle filler
```

```python
from open_pseudonym import Session, Source

s = Session("draft_reply")
masked = s.mask("Hi Dana,\nyour Acme code is 482913.", Source(sender="no-reply@acme.com"))
print(masked.text)                                   # Hi <a fake name>, ... {{OTP_1}}.
print(s.restore(masked.text, reveal_handles=True))   # exactly the original
```

Try `opn demo`. The specification, guides and test vectors live at
<https://github.com/Ishan2036924/open-pseudonym>.

This is pseudonymisation, not anonymisation: what reaches the model is still personal data in law. Apache-2.0.
