"""Tests for shared CLI helper functions."""

from __future__ import annotations

import pytest

from github_security_common import (
    GitHubSecurityCliError,
    expect_dict,
    expect_list,
    filter_non_null_values,
    normalize_repeated_values,
    parse_name_value_pairs,
)


def test_parse_name_value_pairs_trims_and_overwrites_duplicate_keys() -> None:
    """Repeated key/value CLI inputs are normalized into a mapping."""
    result = parse_name_value_pairs([" severity = high ", "state=open", "severity=critical"])

    assert result == {"severity": "critical", "state": "open"}


def test_parse_name_value_pairs_rejects_missing_separator() -> None:
    """Invalid key/value CLI inputs raise a user-facing error."""
    with pytest.raises(GitHubSecurityCliError, match="Expected key=value input"):
        _ = parse_name_value_pairs(["severity"])


def test_parse_name_value_pairs_rejects_empty_key() -> None:
    """Empty keys are rejected before a request payload is built."""
    with pytest.raises(GitHubSecurityCliError, match="Expected non-empty key"):
        _ = parse_name_value_pairs([" = high"])


def test_filter_non_null_values_preserves_falsey_non_null_values() -> None:
    """Only None values are removed from outgoing payloads."""
    result = filter_non_null_values({"empty": "", "false": False, "none": None, "zero": 0})

    assert result == {"empty": "", "false": False, "zero": 0}


def test_normalize_repeated_values_splits_deduplicates_and_preserves_order() -> None:
    """Repeated comma-delimited inputs are normalized for GitHub query parameters."""
    result = normalize_repeated_values(["alice,bob", " alice ", "", "carol,bob"])

    assert result == ["alice", "bob", "carol"]


def test_expect_dict_rejects_non_mapping_payload() -> None:
    """API payload shape validation reports the unexpected type."""
    with pytest.raises(GitHubSecurityCliError, match="received list"):
        _ = expect_dict([], "alert")


def test_expect_list_rejects_non_list_payload() -> None:
    """List payload validation reports the unexpected type."""
    with pytest.raises(GitHubSecurityCliError, match="received dict"):
        _ = expect_list({}, "alerts")
