"""Open Pseudonym: keep personal data away from AI models without making them worse at the task.

The short version:

    from open_pseudonym import Session, Source
    s = Session("draft_reply")
    masked = s.mask(text)          # what the model may see
    reply = s.restore(model_reply)  # what the person reads
"""

from .egress import EgressLeak, EgressLog, Leak, make_checkpoint, verify_log
from .handles import Approval, HandleRefused, Sink, Source, sref_regions
from .jws import Signer
from .policy import (
    LEVELS, Policy, PolicyError, Rule, load_level, load_profile, policy_for, profile_names, suggest_profile,
)
from .session import Masked, RefusedData, Replacement, Resolved, Session
from .vault import Vault, VaultError

__version__ = "0.5.0"

__all__ = [
    "LEVELS", "Approval", "EgressLeak", "EgressLog", "HandleRefused", "Leak", "Masked", "Policy", "PolicyError",
    "RefusedData", "Replacement", "Resolved", "Rule", "Session", "Signer", "Sink", "Source", "Vault", "VaultError",
    "load_level", "load_profile", "make_checkpoint", "policy_for", "profile_names", "sref_regions",
    "suggest_profile", "verify_log", "__version__",
]
