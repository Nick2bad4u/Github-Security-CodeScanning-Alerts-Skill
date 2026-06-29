"""Tests for argument parsing behavior."""

from __future__ import annotations

import sys

import pytest

from github_security_cli import normalize_global_argument_order, parse_args
from github_security_common import GitHubSecurityCliError


def test_parse_args_builds_full_parser_and_normalizes_global_options(monkeypatch: pytest.MonkeyPatch) -> None:
    """Global options may appear after the subcommand."""
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "manage_github_security_alerts.py",
            "list-secret-scanning",
            "--state",
            "open",
            "--json",
            "--repository",
            "octo/repo",
            "--show-secret-values",
        ],
    )

    arguments = parse_args()

    assert arguments.command == "list-secret-scanning"
    assert arguments.json is True
    assert arguments.repository == "octo/repo"
    assert arguments.show_secret_values is True
    assert arguments.state == "open"


def test_parse_args_handles_bulk_update_options(monkeypatch: pytest.MonkeyPatch) -> None:
    """Bulk update parsing preserves repeated alert and assignee values."""
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "manage_github_security_alerts.py",
            "bulk-update-alerts",
            "--surface",
            "code-scanning",
            "--alert",
            "1",
            "--alert",
            "2",
            "--assignee",
            "alice,bob",
            "--dry-run",
        ],
    )

    arguments = parse_args()

    assert arguments.alerts == [1, 2]
    assert arguments.assignees == ["alice,bob"]
    assert arguments.dry_run is True
    assert arguments.surface == "code-scanning"


def test_normalize_global_argument_order_moves_global_values_to_prefix() -> None:
    """Parser normalization keeps subcommand arguments after global settings."""
    result = normalize_global_argument_order(
        ["summary", "--sample-size", "2", "--token-env", "GH_TOKEN", "--json"],
    )

    assert result == ["--token-env", "GH_TOKEN", "--json", "summary", "--sample-size", "2"]


def test_normalize_global_argument_order_rejects_missing_value() -> None:
    """Global options that require values fail with a CLI error."""
    with pytest.raises(GitHubSecurityCliError, match="Expected a value"):
        _ = normalize_global_argument_order(["summary", "--repository"])
