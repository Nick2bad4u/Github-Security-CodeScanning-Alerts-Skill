"""Tests for GitHub API context and request helpers."""
# pyright: reportUnknownArgumentType=false, reportUnknownLambdaType=false

from __future__ import annotations

import io
import subprocess
from email.message import Message
from http import HTTPStatus
from pathlib import Path
from types import SimpleNamespace
from typing import Any, ClassVar, Self
from urllib import error, parse

import pytest

import github_security_api
from github_security_api import (
    GitHubApiError,
    GitHubApiResponse,
    RepoContext,
    api_request,
    build_query_string,
    extract_api_error_message,
    parse_repository_input,
    resolve_context,
    resolve_token,
    run_git,
    safe_api_request,
)
from github_security_common import GitHubSecurityCliError


class FakeUrlopenResponse:
    """Minimal context manager for urllib response tests."""

    status = 201

    def __init__(self, body: bytes, headers: dict[str, str]) -> None:
        """Store a fake response body and headers."""
        super().__init__()
        self._body = body
        self.headers = headers

    def __enter__(self) -> Self:
        """Return the response object for context manager use."""
        return self

    def __exit__(self, *_exc_info: object) -> None:
        """Close without suppressing exceptions."""

    def read(self) -> bytes:
        """Return the configured response body."""
        return self._body


class CompletedProcessFactory:
    """Return subprocess results while preserving the requested git command."""

    calls: ClassVar[list[list[str]]] = []

    @staticmethod
    def success(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        """Return a successful git subprocess result."""
        CompletedProcessFactory.calls.append(command)
        return subprocess.CompletedProcess(command, 0, stdout="origin-url\n", stderr="")

    @staticmethod
    def failure(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        """Return a failed git subprocess result."""
        CompletedProcessFactory.calls.append(command)
        return subprocess.CompletedProcess(command, 1, stdout="", stderr="fatal: nope\n")


def context() -> RepoContext:
    """Create a stable test API context."""
    return RepoContext(
        api_base_url="https://api.example.test",
        owner="octo",
        repo="repo",
        repo_path=Path(),
        token="token-value",
        token_env_name="GITHUB_TOKEN",
        web_base_url="https://github.example.test",
    )


def namespace(**values: object) -> Any:
    """Build a dynamic argparse-like namespace."""
    return SimpleNamespace(**values)


def test_parse_repository_input_accepts_owner_repo_and_urls() -> None:
    """Repository input parsing supports common GitHub remote forms."""
    assert parse_repository_input("octo/repo") == ("github.com", "octo", "repo", "https")
    assert parse_repository_input("git@github.example.test:octo/repo.git") == (
        "github.example.test",
        "octo",
        "repo",
        "https",
    )
    assert parse_repository_input("https://github.example.test/octo/repo") == (
        "github.example.test",
        "octo",
        "repo",
        "https",
    )


@pytest.mark.parametrize("repository", ["", "https://github.com/octo", "not-a-repo"])
def test_parse_repository_input_rejects_invalid_values(repository: str) -> None:
    """Malformed repository inputs fail before any API request is made."""
    with pytest.raises(GitHubSecurityCliError):
        _ = parse_repository_input(repository)


def test_resolve_token_uses_first_non_empty_candidate(monkeypatch: pytest.MonkeyPatch) -> None:
    """Token lookup honors caller-specified environment ordering."""
    monkeypatch.setenv("GH_TOKEN", "  fallback-token  ")

    assert resolve_token(["MISSING_TOKEN", "GH_TOKEN"]) == ("GH_TOKEN", "fallback-token")


def test_resolve_token_reports_candidates(monkeypatch: pytest.MonkeyPatch) -> None:
    """Missing token errors name the variables that were checked."""
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GH_TOKEN", raising=False)

    with pytest.raises(GitHubSecurityCliError, match="GITHUB_TOKEN, GH_TOKEN"):
        _ = resolve_token(None)


def test_resolve_context_uses_explicit_repository_and_enterprise_api(monkeypatch: pytest.MonkeyPatch) -> None:
    """Context resolution derives GitHub Enterprise API URLs from repository hosts."""
    monkeypatch.setenv("GITHUB_TOKEN", "token-value")
    arguments = namespace(
        api_base_url=None,
        repo=".",
        repository="https://github.example.test/octo/repo.git",
        token_envs=None,
        web_base_url=None,
    )

    resolved = resolve_context(arguments)

    assert resolved.api_base_url == "https://github.example.test/api/v3"
    assert resolved.full_name == "octo/repo"
    assert resolved.token_env_name == "GITHUB_TOKEN"
    assert resolved.web_base_url == "https://github.example.test"


def test_resolve_context_uses_git_remote_when_repository_is_omitted(monkeypatch: pytest.MonkeyPatch) -> None:
    """The current checkout remote is used when no repository is supplied."""
    monkeypatch.setenv("GITHUB_TOKEN", "token-value")
    monkeypatch.setattr(github_security_api, "run_git", lambda *_args: "git@github.com:octo/repo.git")
    arguments = namespace(
        api_base_url="https://api.override.test/",
        repo=".",
        repository=None,
        token_envs=None,
        web_base_url="https://web.override.test/",
    )

    resolved = resolve_context(arguments)

    assert resolved.api_base_url == "https://api.override.test"
    assert resolved.full_name == "octo/repo"
    assert resolved.web_base_url == "https://web.override.test"


def test_run_git_returns_stdout_and_reports_stderr(monkeypatch: pytest.MonkeyPatch) -> None:
    """Git subprocess failures are wrapped in a user-facing CLI error."""
    monkeypatch.setattr(subprocess, "run", CompletedProcessFactory.success)
    assert run_git(Path(), "config", "--get", "remote.origin.url") == "origin-url"

    monkeypatch.setattr(subprocess, "run", CompletedProcessFactory.failure)
    with pytest.raises(GitHubSecurityCliError, match="fatal: nope"):
        _ = run_git(Path(), "status")


def test_build_query_string_serializes_lists_booleans_and_nulls() -> None:
    """Query serialization matches GitHub REST API conventions."""
    query = build_query_string({"state": "open", "flag": False, "ids": [1, 2], "empty": None})

    assert query == "?state=open&flag=false&ids=1&ids=2"


def test_extract_api_error_message_prefers_payload_message() -> None:
    """API error rendering falls back cleanly for nonstandard payloads."""
    assert extract_api_error_message({"message": "  denied  "}) == "denied"
    assert extract_api_error_message(" raw text ") == "raw text"
    assert extract_api_error_message({}) == "GitHub API request failed."


def test_api_request_sends_json_body_and_parses_json_response(monkeypatch: pytest.MonkeyPatch) -> None:
    """Successful requests include authentication headers and parse response JSON."""
    captured: dict[str, Any] = {}

    def fake_urlopen(http_request: Any) -> FakeUrlopenResponse:
        captured["url"] = http_request.full_url
        captured["method"] = http_request.get_method()
        captured["body"] = http_request.data
        captured["authorization"] = http_request.headers["Authorization"]
        return FakeUrlopenResponse(
            b'{"ok": true}',
            {"Content-Type": "application/json", "X-RateLimit-Remaining": "42"},
        )

    monkeypatch.setattr("github_security_api.request.urlopen", fake_urlopen)

    response = api_request(
        context(),
        endpoint="/repos/octo/repo/code-scanning/alerts",
        method="patch",
        params={"state": "open"},
        body={"dismissed": False},
    )

    assert captured == {
        "authorization": "Bearer token-value",
        "body": b'{"dismissed": false}',
        "method": "PATCH",
        "url": "https://api.example.test/repos/octo/repo/code-scanning/alerts?state=open",
    }
    assert response == GitHubApiResponse(
        data={"ok": True},
        headers={"content-type": "application/json", "x-ratelimit-remaining": "42"},
        status_code=201,
        url="https://api.example.test/repos/octo/repo/code-scanning/alerts?state=open",
    )


def test_api_request_handles_plain_text_response(monkeypatch: pytest.MonkeyPatch) -> None:
    """Non-JSON success responses are decoded as text."""
    monkeypatch.setattr(
        "github_security_api.request.urlopen",
        lambda _request: FakeUrlopenResponse(b"accepted", {"Content-Type": "text/plain"}),
    )

    response = api_request(context(), endpoint="https://api.example.test/raw", accept="text/plain")

    assert response.data == "accepted"


def test_api_request_rejects_plaintext_http_endpoints() -> None:
    """Token-bearing API requests must not use plaintext HTTP URLs."""
    endpoint = parse.urlunparse(("http", "api.example.test", "/raw", "", "", ""))

    with pytest.raises(GitHubSecurityCliError, match="HTTPS URLs"):
        _ = api_request(context(), endpoint=endpoint)


def test_api_request_wraps_http_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    """HTTP errors retain endpoint, URL, status, and parsed response details."""
    headers = Message()
    headers.add_header("Content-Type", "application/json")

    def fake_urlopen(_request: object) -> FakeUrlopenResponse:
        raise error.HTTPError(
            "https://api.example.test/repos/octo/repo",
            403,
            "Forbidden",
            headers,
            io.BytesIO(b'{"message": "blocked"}'),
        )

    monkeypatch.setattr("github_security_api.request.urlopen", fake_urlopen)

    with pytest.raises(GitHubApiError) as exc_info:
        _ = api_request(context(), endpoint="/repos/octo/repo")

    assert str(exc_info.value) == "blocked"
    assert exc_info.value.status_code == HTTPStatus.FORBIDDEN
    assert exc_info.value.response_data == {"message": "blocked"}


def test_safe_api_request_returns_structured_success_and_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """Safe requests convert request exceptions into JSON-serializable payloads."""

    def raise_api_error(*_args: object, **_kwargs: object) -> GitHubApiResponse:
        raise GitHubApiError(
            endpoint="/endpoint",
            message="bad request",
            response_data={"message": "bad request"},
            status_code=400,
            url="https://api.example.test/endpoint",
        )

    monkeypatch.setattr(
        github_security_api,
        "api_request",
        lambda *_args, **_kwargs: GitHubApiResponse({}, {}, 200, "url"),
    )
    assert safe_api_request(context(), endpoint="/endpoint") == {
        "data": {},
        "headers": {},
        "ok": True,
        "status_code": 200,
        "url": "url",
    }

    monkeypatch.setattr(github_security_api, "api_request", raise_api_error)
    assert safe_api_request(context(), endpoint="/endpoint") == {
        "error": {
            "endpoint": "/endpoint",
            "message": "bad request",
            "response": {"message": "bad request"},
            "status_code": 400,
            "url": "https://api.example.test/endpoint",
        },
        "ok": False,
    }
