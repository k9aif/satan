"""
Tests for ToolAuthorizationCheck's host-matching logic.

Regression coverage for a substring-containment bypass: the check used to do
`any(approved in host for approved in approved_backends)`, which let
"evil-localhost.attacker.com" through because it contains the substring
"localhost". Fixed to exact-match or dot-boundary suffix match.
"""

import os
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "k9-aif-framework"))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import pytest

from k9x_satan.target.tool_authorization_check import ToolAuthorizationCheck, _extract_host, _host_matches


# ── _host_matches: exact / suffix / attack cases ──────────────────────────────

def test_exact_match():
    assert _host_matches("localhost", "localhost") is True


def test_dot_suffix_match():
    assert _host_matches("api.localhost", "localhost") is True
    assert _host_matches("deep.nested.localhost", "localhost") is True


def test_substring_attack_rejected():
    # The regression this test guards against.
    assert _host_matches("evil-localhost.attacker.com", "localhost") is False


def test_prefix_attack_rejected():
    assert _host_matches("localhost.attacker.com", "localhost") is False


def test_bare_substring_without_dot_boundary_rejected():
    assert _host_matches("notlocalhost", "localhost") is False


def test_case_variation_matches():
    assert _host_matches("LOCALHOST", "localhost") is True
    assert _host_matches("Api.LocalHost", "localhost") is True


def test_ip_literal_exact_match():
    assert _host_matches("127.0.0.1", "127.0.0.1") is True


def test_ip_literal_prefix_attack_rejected():
    assert _host_matches("127.0.0.1.attacker.com", "127.0.0.1") is False


# ── _extract_host: URL / bare host / port / IDN handling ─────────────────────

def test_extract_host_from_full_url():
    assert _extract_host("http://localhost:9999/search") == "localhost"


def test_extract_host_strips_port_bare_host():
    assert _extract_host("localhost:9999") == "localhost"


def test_extract_host_case_normalized():
    assert _extract_host("http://LOCALHOST:9999") == "localhost"


def test_extract_host_ip_literal():
    assert _extract_host("http://127.0.0.1:11434/api/generate") == "127.0.0.1"


def test_extract_host_punycode_idn():
    # xn-- prefixed hosts pass through unchanged — no punycode decoding is
    # performed, so an IDN homograph of an approved host will NOT match it
    # (correctly rejected, not silently accepted).
    assert _extract_host("http://xn--80ak6aa92e.com") == "xn--80ak6aa92e.com"
    assert _host_matches("xn--80ak6aa92e.com", "apple.com") is False


# ── Full check() integration ──────────────────────────────────────────────────

def _make_check(approved_backends=None):
    cfg = {"security": {"approved_backends": approved_backends or ["localhost", "127.0.0.1"]}}
    return ToolAuthorizationCheck(cfg)


def test_check_passes_approved_backend():
    check = _make_check()
    result = check.check({"search_backend": "http://localhost:9999"})
    assert result.passed


def test_check_blocks_substring_attack_backend():
    check = _make_check()
    result = check.check({"search_backend": "http://evil-localhost.attacker.com"})
    assert result.blocked


def test_check_blocks_unapproved_tool_name():
    check = _make_check()
    result = check.check({"tool_name": "unregistered_shell_exec"})
    assert result.blocked


def test_check_passes_approved_tool_name():
    check = _make_check()
    result = check.check({"tool_name": "fake_search"})
    assert result.passed
