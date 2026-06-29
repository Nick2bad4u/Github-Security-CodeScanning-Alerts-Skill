"""Tests for security alert operation helpers."""
# pyright: reportUnknownArgumentType=false, reportUnknownLambdaType=false, reportUnknownVariableType=false

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import github_security_operations
from github_security_api import GitHubApiResponse, RepoContext
from github_security_common import GitHubSecurityCliError
from github_security_operations import (
    build_bulk_update_namespace,
    build_code_scanning_query,
    build_code_scanning_update_payload,
    build_dependabot_query,
    build_dependabot_update_payload,
    build_secret_scanning_query,
    build_secret_scanning_update_payload,
    build_summary,
    bulk_update_alerts,
    classify_malware_alerts,
    fetch_code_scanning_autofix,
    fetch_repository_overview,
    get_alert_ghsa_id,
    get_bulk_mutation_target_state,
    handle_command,
    maybe_raise_if_not_malware,
    run_api_call,
    summarize_alert_collection,
    summarize_selected_alert,
    update_code_scanning_alert,
)


def namespace(**values: object) -> Any:
    """Build a dynamic argparse-like namespace."""
    return SimpleNamespace(**values)


def context() -> RepoContext:
    """Create a stable test API context."""
    return RepoContext(
        api_base_url="https://api.example.test",
        owner="octo",
        repo="repo",
        repo_path=Path(__file__),
        token="token",
        token_env_name="GITHUB_TOKEN",
        web_base_url="https://github.example.test",
    )


def code_scanning_args(**overrides: object) -> Any:
    """Build code scanning argument defaults."""
    values: dict[str, object] = {
        "alert": 7,
        "assignees": None,
        "clear_assignees": False,
        "comment": None,
        "create_request": False,
        "direction": None,
        "dismissed_reason": None,
        "dry_run": False,
        "page": 1,
        "per_page": 30,
        "pr": None,
        "ref": None,
        "severity": None,
        "sort": None,
        "state": "open",
        "tool_guid": None,
        "tool_name": None,
        "assignees_filter": None,
        "assignee_filter": None,
    }
    values.update(overrides)
    values["assignees"] = values.pop("assignees_filter", values["assignees"])
    return namespace(**values)


def dependabot_args(**overrides: object) -> Any:
    """Build Dependabot argument defaults."""
    values: dict[str, object] = {
        "after": None,
        "alert": 7,
        "assignee": None,
        "assignees": None,
        "before": None,
        "clear_assignees": False,
        "comment": None,
        "direction": None,
        "dismissed_reason": None,
        "dry_run": False,
        "ecosystem": None,
        "epss_percentage": None,
        "has_filter": None,
        "manifest": None,
        "package": None,
        "per_page": 30,
        "scope": None,
        "severity": None,
        "sort": None,
        "state": "open",
    }
    values.update(overrides)
    return namespace(**values)


def secret_args(**overrides: object) -> Any:
    """Build secret scanning argument defaults."""
    values: dict[str, object] = {
        "alert": 7,
        "assignee": None,
        "comment": None,
        "direction": None,
        "dry_run": False,
        "is_multi_repo": False,
        "is_publicly_leaked": False,
        "page": 1,
        "per_page": 30,
        "resolution": None,
        "secret_type": None,
        "show_secret_values": False,
        "sort": None,
        "state": "open",
        "unassign": False,
        "validity": None,
    }
    values.update(overrides)
    return namespace(**values)


def test_query_builders_filter_nulls_and_preserve_flags() -> None:
    """List query builders map CLI names to GitHub REST parameter names."""
    assert build_code_scanning_query(
        code_scanning_args(tool_name="CodeQL", state="open", pr=12, assignees_filter="alice"),
    ) == {"assignees": "alice", "page": 1, "per_page": 30, "pr": 12, "state": "open", "tool_name": "CodeQL"}

    assert build_dependabot_query(
        dependabot_args(ecosystem="npm", has_filter="patch", package="pkg"),
    ) == {"ecosystem": "npm", "has": "patch", "package": "pkg", "per_page": 30, "state": "open"}

    assert build_secret_scanning_query(
        secret_args(is_multi_repo=True, is_publicly_leaked=True, show_secret_values=False),
    ) == {
        "hide_secret": True,
        "is_multi_repo": True,
        "is_publicly_leaked": True,
        "page": 1,
        "per_page": 30,
        "state": "open",
    }


def test_update_payload_builders_validate_state_specific_fields() -> None:
    """Mutation payloads enforce GitHub API state rules before requests are sent."""
    assert build_code_scanning_update_payload(
        code_scanning_args(
            state="dismissed",
            dismissed_reason="false positive",
            comment="reviewed",
            create_request=True,
            assignees_filter=["alice,bob"],
        ),
    ) == {
        "assignees": ["alice", "bob"],
        "create_request": True,
        "dismissed_comment": "reviewed",
        "dismissed_reason": "false positive",
        "state": "dismissed",
    }
    assert build_dependabot_update_payload(
        dependabot_args(state="open", clear_assignees=True),
    ) == {"assignees": [], "state": "open"}
    assert build_secret_scanning_update_payload(
        secret_args(state="resolved", resolution="revoked", comment="rotated", assignee="alice"),
    ) == {
        "assignee": "alice",
        "resolution": "revoked",
        "resolution_comment": "rotated",
        "state": "resolved",
    }

    with pytest.raises(GitHubSecurityCliError, match="required when dismissing"):
        _ = build_code_scanning_update_payload(code_scanning_args(state="dismissed"))
    with pytest.raises(GitHubSecurityCliError, match="only be used when state is dismissed"):
        _ = build_dependabot_update_payload(dependabot_args(state="open", comment="nope"))
    with pytest.raises(GitHubSecurityCliError, match="Use either --assignee or --unassign"):
        _ = build_secret_scanning_update_payload(secret_args(unassign=True, assignee="alice"))


def test_fetch_and_update_helpers_use_expected_endpoints(monkeypatch: pytest.MonkeyPatch) -> None:
    """Operation helpers call the GitHub endpoints they advertise."""
    calls: list[dict[str, object]] = []

    def fake_api_request(_context: RepoContext, **kwargs: object) -> GitHubApiResponse:
        calls.append(kwargs)
        return GitHubApiResponse({"number": 7}, {}, 200, "url")

    monkeypatch.setattr(github_security_operations, "api_request", fake_api_request)

    assert update_code_scanning_alert(context(), code_scanning_args(dry_run=True)) == {
        "dry_run": True,
        "endpoint": "/repos/octo/repo/code-scanning/alerts/7",
        "payload": {"state": "open"},
    }
    assert update_code_scanning_alert(context(), code_scanning_args()) == {"number": 7}
    assert calls[-1] == {
        "body": {"state": "open"},
        "endpoint": "/repos/octo/repo/code-scanning/alerts/7",
        "method": "PATCH",
    }


def test_code_scanning_autofix_returns_error_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    """Autofix lookup failures are returned as payloads instead of raising."""
    monkeypatch.setattr(
        github_security_operations,
        "safe_api_request",
        lambda *_args, **_kwargs: {"error": {"message": "not enabled"}, "ok": False},
    )

    assert fetch_code_scanning_autofix(context(), 7) == {"error": {"message": "not enabled"}}


def test_malware_classification_handles_success_failures_and_missing_ghsa(monkeypatch: pytest.MonkeyPatch) -> None:
    """Dependabot malware classification enriches only confirmed malware advisories."""
    alerts = [
        {"number": 1, "security_advisory": {"ghsa_id": "GHSA-malware"}},
        {"number": 2, "security_advisory": {"identifiers": [{"type": "GHSA", "value": "GHSA-lib"}]}},
        {"number": 3, "security_advisory": {"ghsa_id": "GHSA-error"}},
        {"number": 4, "security_advisory": {}},
    ]
    advisories = {
        "GHSA-error": {"error": {"message": "rate limited"}},
        "GHSA-lib": {"type": "reviewed"},
        "GHSA-malware": {"type": "malware"},
    }
    monkeypatch.setattr(
        github_security_operations,
        "fetch_global_advisory_type",
        lambda _context, ghsa_id, _cache: advisories[ghsa_id],
    )

    malware_alerts, lookup_failures = classify_malware_alerts(context(), alerts)

    assert get_alert_ghsa_id(alerts[1]) == "GHSA-lib"
    assert malware_alerts == [
        {
            "malware_advisory": {"type": "malware"},
            "number": 1,
            "security_advisory": {"ghsa_id": "GHSA-malware"},
        }
    ]
    assert lookup_failures == [{"alert_number": 3, "error": {"message": "rate limited"}, "ghsa_id": "GHSA-error"}]


def test_maybe_raise_if_not_malware_validates_advisory_type(monkeypatch: pytest.MonkeyPatch) -> None:
    """Malware-specific commands reject non-malware Dependabot alerts."""
    monkeypatch.setattr(
        github_security_operations,
        "fetch_dependabot_alert",
        lambda _context, _alert_number: {"number": 7, "security_advisory": {"ghsa_id": "GHSA-lib"}},
    )
    monkeypatch.setattr(
        github_security_operations,
        "fetch_global_advisory_type",
        lambda _context, _ghsa_id, _cache: {"type": "malware"},
    )

    assert maybe_raise_if_not_malware(context(), 7, {}) == {
        "malware_advisory": {"type": "malware"},
        "number": 7,
        "security_advisory": {"ghsa_id": "GHSA-lib"},
    }

    monkeypatch.setattr(
        github_security_operations,
        "fetch_global_advisory_type",
        lambda _context, _ghsa_id, _cache: {"type": "reviewed"},
    )
    with pytest.raises(GitHubSecurityCliError, match="not backed by a malware advisory"):
        _ = maybe_raise_if_not_malware(context(), 7, {})


def test_repository_overview_and_summary_use_safe_request_payloads(monkeypatch: pytest.MonkeyPatch) -> None:
    """Summary builders preserve success and failure sections across alert families."""

    def fake_api_request(_context: RepoContext, **_kwargs: object) -> GitHubApiResponse:
        return GitHubApiResponse(
            {
                "html_url": "https://github.example.test/octo/repo",
                "private": False,
                "security_and_analysis": {"advanced_security": {"status": "enabled"}},
                "visibility": "public",
            },
            {},
            200,
            "url",
        )

    def fake_safe_request(_context: RepoContext, *, endpoint: str, **_kwargs: object) -> dict[str, object]:
        if "dependabot" in endpoint:
            return {"data": [{"number": 1, "state": "open"}], "ok": True}
        if "secret-scanning" in endpoint:
            return {"error": {"message": "disabled"}, "ok": False}
        return {"data": [{"number": 2, "state": "dismissed"}], "ok": True}

    monkeypatch.setattr(github_security_operations, "api_request", fake_api_request)
    monkeypatch.setattr(github_security_operations, "safe_api_request", fake_safe_request)
    monkeypatch.setattr(github_security_operations, "classify_malware_alerts", lambda *_args: ([], []))

    overview = fetch_repository_overview(context())
    summary = build_summary(context(), namespace(per_page=10, sample_size=1))

    assert overview["full_name"] == "octo/repo"
    assert summary["sections"]["code_scanning"]["counts_by_state"] == {"dismissed": 1}
    assert summary["sections"]["secret_scanning"] == {"error": {"message": "disabled"}, "ok": False}
    assert summary["sections"]["malware"]["total"] == 0


def test_summarize_alert_collection_returns_error_without_indexing_data() -> None:
    """Failed safe requests pass through error details directly."""
    assert summarize_alert_collection(
        {"error": {"message": "forbidden"}, "ok": False},
        sample_size=1,
        summary_kind="code_scanning",
    ) == {"error": {"message": "forbidden"}, "ok": False}


def test_bulk_update_dry_run_builds_selection_and_update_preview(monkeypatch: pytest.MonkeyPatch) -> None:
    """Bulk update dry runs report selected alerts without mutating GitHub state."""
    monkeypatch.setattr(
        github_security_operations,
        "fetch_code_scanning_alerts",
        lambda _context, _query: [{"html_url": "url", "number": 7, "rule": {"id": "rule"}, "state": "open"}],
    )
    arguments = namespace(
        alert=None,
        alerts=None,
        assignee_filter=None,
        assignees=["alice"],
        clear_assignees=False,
        comment=None,
        create_request=False,
        direction=None,
        dismissed_reason=None,
        dry_run=True,
        limit=1,
        page=1,
        per_page=30,
        pr=None,
        ref=None,
        select_state="open",
        severity=None,
        sort=None,
        surface="code-scanning",
        target_state="dismissed",
        tool_guid=None,
        tool_name=None,
    )

    result = bulk_update_alerts(context(), arguments)

    assert result["selected_count"] == 1
    assert result["selected_alerts"][0]["rule_id"] == "rule"
    assert result["selected_alerts"][0]["surface"] == "code-scanning"
    assert result["update_requests"] == [
        {
            "alert": 7,
            "assignees": ["alice"],
            "clear_assignees": False,
            "comment": None,
            "create_request": False,
            "dismissed_reason": None,
            "dry_run": True,
            "state": "dismissed",
        }
    ]


def test_bulk_namespace_and_target_state_validation() -> None:
    """Bulk mutation namespaces normalize per-surface update arguments."""
    base_arguments = namespace(
        assignees=["alice"],
        clear_assignees=False,
        comment="done",
        dismissed_reason="tolerable_risk",
        dry_run=True,
        resolution="revoked",
        target_state="resolved",
    )
    secret_namespace = build_bulk_update_namespace(
        alert={"number": 8, "state": "open"},
        arguments=base_arguments,
        surface="secret-scanning",
    )

    assert secret_namespace.__dict__ == {
        "alert": 8,
        "assignee": "alice",
        "comment": "done",
        "dry_run": True,
        "resolution": "revoked",
        "state": "resolved",
        "unassign": False,
    }

    with pytest.raises(GitHubSecurityCliError, match="does not support target state"):
        _ = get_bulk_mutation_target_state(arguments=base_arguments, current_state="open", surface="dependabot")
    code_scanning_arguments = namespace(
        assignees=None,
        clear_assignees=False,
        comment=None,
        create_request=False,
        dismissed_reason=None,
        dry_run=True,
        target_state="open",
    )
    with pytest.raises(GitHubSecurityCliError, match="missing an integer alert number"):
        _ = build_bulk_update_namespace(
            alert={"state": "open"},
            arguments=code_scanning_arguments,
            surface="code-scanning",
        )


def test_summarize_selected_alert_extracts_surface_specific_fields() -> None:
    """Selected alert summaries include the fields useful for review before mutation."""
    dependabot_summary = summarize_selected_alert(
        {
            "dependency": {"manifest_path": "package-lock.json"},
            "html_url": "url",
            "number": 3,
            "security_vulnerability": {"package": {"ecosystem": "npm", "name": "pkg"}, "severity": "high"},
            "state": "open",
        },
        "dependabot",
    )
    secret_summary = summarize_selected_alert(
        {"html_url": "secret-url", "number": 4, "resolution": None, "secret_type": "token", "state": "open"},
        "secret-scanning",
    )

    assert dependabot_summary["package"] == "pkg"
    assert dependabot_summary["manifest_path"] == "package-lock.json"
    assert secret_summary["secret_type"] == "token"


def test_handle_command_dispatches_and_rejects_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    """Command dispatch maps parsed names to operation helpers."""
    monkeypatch.setattr(github_security_operations, "fetch_secret_scan_history", lambda _context: {"scan": "ok"})

    assert handle_command(context(), namespace(command="secret-scan-history")) == {"scan": "ok"}
    with pytest.raises(GitHubSecurityCliError, match="Unsupported command"):
        _ = handle_command(context(), namespace(command="future"))


def test_run_api_call_parses_query_params_and_json_body(monkeypatch: pytest.MonkeyPatch) -> None:
    """Raw API calls preserve caller-supplied method, query params, and JSON body."""
    captured: dict[str, object] = {}

    def fake_api_request(_context: RepoContext, **kwargs: object) -> GitHubApiResponse:
        captured.update(kwargs)
        return GitHubApiResponse({"ok": True}, {}, 202, "https://api.example.test/custom")

    monkeypatch.setattr(github_security_operations, "api_request", fake_api_request)

    result = run_api_call(
        context(),
        namespace(
            body_json='{"enabled": true}',
            endpoint="/custom",
            method="post",
            query_params=["state=open", "severity=high"],
        ),
    )

    assert captured == {
        "body": {"enabled": True},
        "endpoint": "/custom",
        "method": "post",
        "params": {"severity": "high", "state": "open"},
    }
    assert result == {"data": {"ok": True}, "status_code": 202, "url": "https://api.example.test/custom"}
