"""A whole round trip without any model: mask, pretend to be the model, restore, check, sign.

Run from the repository root: python examples/quickstart.py
"""

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "sdk/python/src"))

from open_pseudonym import EgressLog, Session, Signer, Sink, Source, verify_log  # noqa: E402

EMAIL = """From: Dana Reyes <dana.reyes@gmail.com>
Hi Sam,
Can we move Thursday's call to March 12, 2026? My number is (617) 555-0142.
Your Acme verification code is 482913. It expires in 10 minutes.
Dana"""

session = Session("browse_and_fill")
masked = session.mask(EMAIL, Source(sender="no-reply@acme.com"))
print("What the model sees:\n" + masked.text + "\n")
print("\n".join("Note: " + n for n in masked.notes) + "\n")

# Pretend the model answered with a reply and a tool call that uses the handle.
first_name = masked.text.split("Hi ")[1].split(",")[0]
answer = f"Thursday works, {first_name}. Signing in now."
tool_args = {"selector": "#code", "text": "{{OTP_1}}"}

print("What the person reads:\n" + session.restore(answer) + "\n")
filled = session.resolve_args(tool_args, Sink(tool="browser_type", site="https://login.acme.com"))
print("What the login form receives:", filled.args["text"])

with tempfile.TemporaryDirectory() as folder:
    signer = Signer.generate()
    receipt = session.record_egress(EgressLog(folder, signer), masked.text.encode(), "api.example.com")
    print("Receipt starts:", receipt[:40] + "...")
    print("Verification:", verify_log(folder, signer.public_key, session.vault))
