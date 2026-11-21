"""Hosts and text from untrusted input must cost time linear in their length.

The TypeScript SDK used `/\\.+$/` and `/[ws]+$/`, which backtrack quadratically on a long run of dots or spaces that
is not at the end (CodeQL js/polynomial-redos). This SDK uses str.rstrip and str.strip there, which are linear, but
`registrable` tried every suffix length of a host and was quadratic too: 12 s for 50,000 dots. These inputs keep both
SDKs honest.
"""

import time

from open_pseudonym import Sink, Source
from open_pseudonym.detect import _sentence_start
from open_pseudonym.fakes import is_public_suffix, registrable
from open_pseudonym.handles import site_matches

N = 50_000
DOTS = "a" + "." * N + "a"
LABELS = "a." * N + "com"
SPACES = "a" + " " * N + "a"
LIMIT = 0.25  # seconds; the quadratic forms took seconds to minutes here, the linear ones well under 10 ms


def fast(label, f):
    t = time.perf_counter()
    f()
    took = time.perf_counter() - t
    assert took < LIMIT, f"{label} took {took * 1000:.0f} ms on a {N}-character input"


def test_host_helpers_stay_linear():
    fast("is_public_suffix", lambda: is_public_suffix(DOTS))
    fast("registrable (dots)", lambda: registrable(DOTS))
    fast("registrable (labels)", lambda: registrable(LABELS))
    fast("bound_site", lambda: Source(sender="x@" + DOTS).bound_site())
    fast("site_matches(site)", lambda: site_matches(DOTS, ["acme.com"]))
    fast("site_matches(allowed)", lambda: site_matches("acme.com", [DOTS, "*." + DOTS]))
    fast("_sentence_start", lambda: _sentence_start(SPACES, len(SPACES) - 1))


def test_registrable_keeps_its_answers():
    assert registrable("login.acme.com") == "acme.com"
    assert registrable("acme.github.io") == "acme.github.io"
    assert registrable("a.b.acme.co.uk.") == "acme.co.uk"
    assert registrable("com") == "com"


def test_the_public_api_stays_fast(make_session):
    s = make_session("browse_and_fill")
    fast("mask with a hostile sender", lambda: s.mask("Your code is 482913.", Source(sender="x@" + DOTS)))

    def resolve():
        try:
            s.resolve_args({"t": "{{OTP_1}}"}, Sink("type", DOTS))
        except Exception:  # refused is fine; only the time matters
            pass

    fast("resolve_args on a hostile sink", resolve)
    fast("mask an email with a deep host", lambda: s.mask("write to x@" + "a." * 2000 + "com"))
