import pytest

from open_pseudonym import Session, Vault

NOW = 1793836800  # 2026-11-05 00:00 UTC, fixed so dates and expiry are repeatable


@pytest.fixture
def make_session():
    def make(profile="draft_reply", seed=bytes(32), now=NOW, **kw):
        clock = kw.pop("clock", lambda: now)
        return Session(profile, Vault(seed=seed, created=now), clock=clock, **kw)

    return make
