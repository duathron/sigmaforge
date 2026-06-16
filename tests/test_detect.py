"""Property/fuzz tests for the parse boundary.

Framework QA policy: garbage in -> never crash, sensible fallback. Combines a
fixed adversarial corpus with Hypothesis property-based testing, which generates
inputs you would never think to write by hand (the class of bug mocks miss).
"""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from sigmaforge.detect import classify

GARBAGE = [
    "",
    "   ",
    "\n",
    "report.dll",
    "/etc/passwd",
    "C:\\Windows\\system32",
    "this is a sentence.",
    "unicode-ü",
    "boom",
    "a" * 5000,
    "...",
    "1.2.3",
    "999.999.999.999",
    "http://",
    "@@@",
    "{}",
    "[]",
    "null",
]


@pytest.mark.parametrize("value", GARBAGE)
def test_garbage_never_crashes_and_falls_back(value):
    result = classify(value)
    assert isinstance(result, str)
    assert result in {"ipv4", "hash", "domain", "unknown"}


@pytest.mark.parametrize("value", [None, 123, 4.5, b"bytes", [], {}])
def test_non_string_inputs_return_unknown(value):
    assert classify(value) == "unknown"


def test_known_types():
    assert classify("8.8.8.8") == "ipv4"
    assert classify("example.com") == "domain"
    assert classify("a" * 40) == "hash"


@given(st.text())
def test_property_any_text_never_crashes(value):
    """Hypothesis generates arbitrary text — classify must never raise."""
    assert classify(value) in {"ipv4", "hash", "domain", "unknown"}


@given(st.one_of(st.none(), st.integers(), st.floats(), st.binary(), st.lists(st.text())))
def test_property_any_object_returns_str(value):
    """Arbitrary non-string objects must return a string, never raise."""
    assert isinstance(classify(value), str)
