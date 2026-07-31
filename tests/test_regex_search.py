"""The domain regex filter is caller-supplied input reaching a query planner,
so the guard around it is the part worth pinning.

Two jobs, split deliberately. This validator rejects what is *malformed* and
returns a readable 400; it does not and cannot reject what is merely *slow* —
a pattern's running time is not decidable from its text, so runaway
backtracking is the statement timeout's problem, not this function's. The tests
below assert exactly that division, so nobody later "improves" the validator
into a false sense of safety.
"""

from __future__ import annotations

import pytest

from tlsrep.application.use_cases import BadRequest, UseCases

ok = UseCases._validated_regex


def test_ordinary_domain_patterns_pass():
    assert ok(r"\.appsflyer\.com$") == r"\.appsflyer\.com$"
    assert ok("^(login|auth|sso|account)\\.") == "^(login|auth|sso|account)\\."


def test_surrounding_whitespace_is_trimmed():
    assert ok("  ^api\\.  ") == "^api\\."


@pytest.mark.parametrize("bad", ["", "   "])
def test_empty_is_rejected(bad):
    with pytest.raises(BadRequest, match="empty"):
        ok(bad)


@pytest.mark.parametrize(
    "bad",
    [
        "(unclosed",
        "[a-",
        "*leading-quantifier",
        "a{2,1}",
    ],
)
def test_malformed_patterns_are_rejected(bad):
    with pytest.raises(BadRequest, match="not a valid regular expression"):
        ok(bad)


def test_over_length_is_rejected():
    with pytest.raises(BadRequest, match="longer than"):
        ok("a" * (UseCases.MAX_PATTERN + 1))


def test_at_the_length_limit_is_accepted():
    assert ok("a" * UseCases.MAX_PATTERN)


def test_catastrophic_backtracking_is_accepted_here():
    """Not an oversight — the point.

    `(a+)+$` is valid regex and compiles instantly; what it costs is decided at
    match time against the data. Rejecting it would mean rejecting a whole
    shape of legitimate pattern on a guess. It is allowed through, and the
    statement timeout in the repository is what bounds it.
    """
    assert ok("(a+)+$")
