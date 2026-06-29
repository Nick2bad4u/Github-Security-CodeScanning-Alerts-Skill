"""GitHub REST API helpers for the security alert CLI."""

from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast
from urllib import error, parse, request

from github_security_common import GitHubSecurityCliError, expect_dict

DEFAULT_ACCEPT = "application/vnd.github+json"
DEFAULT_API_VERSION = "2026-03-10"
DEFAULT_TOKEN_ENVS = ("GITHUB_TOKEN", "GH_TOKEN")
GITHUB_DOT_COM_HOST = "github.com"
GITHUB_DOT_COM_API_BASE = "https://api.github.com"
MIN_REPOSITORY_PATH_SEGMENTS = 2
ABSOLUTE_URL_SCHEMES = frozenset({"http", "https"})


@dataclass(frozen=True)
class RepoContext:
    """Resolved repository and authentication context."""

    api_base_url: str
    owner: str
    repo: str
    repo_path: Path
    token: str
    token_env_name: str
    web_base_url: str

    @property
    def full_name(self) -> str:
        """Return the owner/repository name used by GitHub APIs."""
        return f"{self.owner}/{self.repo}"


@dataclass(frozen=True)
class GitHubApiResponse:
    """HTTP response wrapper used by the helper."""

    data: Any
    headers: dict[str, str]
    status_code: int
    url: str


class GitHubApiError(GitHubSecurityCliError):
    """Raised when the GitHub API returns a non-success response."""

    def __init__(
        self,
        *,
        endpoint: str,
        message: str,
        response_data: Any,
        status_code: int,
        url: str,
    ) -> None:
        """Initialize the error with HTTP context for callers and renderers."""
        super().__init__(message)
        self.endpoint = endpoint
        self.response_data = response_data
        self.status_code = status_code
        self.url = url


def run_git(repo_path: Path, *arguments: str) -> str:
    """Run a git command inside the target repository."""
    completed = subprocess.run(
        ["git", "-C", str(repo_path), *arguments],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        stderr = completed.stderr.strip()
        raise GitHubSecurityCliError(
            f"Git command failed in '{repo_path}': git {' '.join(arguments)}" + (f"\n{stderr}" if stderr else "")
        )

    return completed.stdout.strip()


def parse_repository_input(repository: str) -> tuple[str, str, str, str]:
    """Parse owner/repo or a repository URL into host/owner/repo/base URL pieces."""
    repository = repository.strip()
    if not repository:
        raise GitHubSecurityCliError("Repository input cannot be empty.")

    remote_match = re.fullmatch(
        r"git@(?P<host>[^:]+):(?P<owner>[^/]+)/(?P<repo>[^/]+)(?:\.git)?",
        repository,
    )
    if remote_match:
        return (
            remote_match.group("host"),
            remote_match.group("owner"),
            remote_match.group("repo").removesuffix(".git"),
            "https",
        )

    owner_repo_match = re.fullmatch(r"(?P<owner>[^/:]+)/(?P<repo>[^/:]+)", repository)
    if owner_repo_match:
        return (
            GITHUB_DOT_COM_HOST,
            owner_repo_match.group("owner"),
            owner_repo_match.group("repo"),
            "https",
        )

    parsed = parse.urlparse(repository)
    if parsed.scheme and parsed.netloc:
        path_segments = [segment for segment in parsed.path.split("/") if segment]
        if len(path_segments) < MIN_REPOSITORY_PATH_SEGMENTS:
            raise GitHubSecurityCliError(f"Could not parse owner/repo from repository URL '{repository}'.")

        repo_name = path_segments[-1]
        repo_name = repo_name.removesuffix(".git")

        return parsed.netloc, path_segments[-2], repo_name, parsed.scheme

    raise GitHubSecurityCliError(f"Unsupported repository input '{repository}'. Use owner/repo or a GitHub URL.")


def parse_remote_url(remote_url: str) -> tuple[str, str, str, str]:
    """Parse a git remote URL into host/owner/repo/scheme."""
    return parse_repository_input(remote_url)


def resolve_token(token_envs: list[str] | None) -> tuple[str, str]:
    """Resolve the first non-empty token from the candidate environment variables."""
    candidates = token_envs or list(DEFAULT_TOKEN_ENVS)

    for candidate in candidates:
        token = os.environ.get(candidate)
        if token and token.strip():
            return candidate, token.strip()

    candidate_text = ", ".join(candidates)
    message = (
        f"Could not find a GitHub token in any configured environment variable ({candidate_text}).\n"
        "Populate one first, for example in PowerShell:\n"
        "$env:GITHUB_TOKEN = Get-Secret GITHUB_TOKEN -AsPlainText"
    )
    raise GitHubSecurityCliError(message)


def resolve_context(arguments: Any) -> RepoContext:
    """Resolve repository ownership, host, and token context."""
    repo_path = Path(arguments.repo).expanduser().resolve()
    token_env_name, token = resolve_token(arguments.token_envs)

    if arguments.repository is not None:
        host, owner, repo_name, scheme = parse_repository_input(arguments.repository)
    else:
        remote_url = run_git(repo_path, "config", "--get", "remote.origin.url")
        host, owner, repo_name, scheme = parse_remote_url(remote_url)

    web_base_url = (arguments.web_base_url or f"{scheme}://{host}").rstrip("/")
    if arguments.api_base_url is not None:
        api_base_url = arguments.api_base_url.rstrip("/")
    elif host.lower() == GITHUB_DOT_COM_HOST:
        api_base_url = GITHUB_DOT_COM_API_BASE
    else:
        api_base_url = f"{scheme}://{host.rstrip('/')}/api/v3"

    return RepoContext(
        api_base_url=api_base_url,
        owner=owner,
        repo=repo_name,
        repo_path=repo_path,
        token=token,
        token_env_name=token_env_name,
        web_base_url=web_base_url,
    )


def require_https_url(url: str) -> None:
    """Reject token-bearing API requests over plaintext HTTP."""
    if parse.urlparse(url).scheme.lower() == "http":
        raise GitHubSecurityCliError("GitHub API requests must use HTTPS URLs.")


def normalize_query_value(value: Any) -> str:
    """Normalize query-parameter values to GitHub-friendly strings."""
    if isinstance(value, bool):
        return "true" if value else "false"

    return str(value)


def build_query_string(params: dict[str, Any] | None) -> str:
    """Serialize query parameters, omitting null values."""
    if not params:
        return ""

    normalized_params: list[tuple[str, str]] = []

    for key, value in params.items():
        if value is None:
            continue
        if isinstance(value, list):
            items = cast("list[object]", value)
            normalized_params.extend((key, normalize_query_value(item)) for item in items)
            continue
        normalized_params.append((key, normalize_query_value(value)))

    if not normalized_params:
        return ""

    return "?" + parse.urlencode(normalized_params, doseq=True)


def extract_api_error_message(payload: Any) -> str:
    """Extract a readable message from a GitHub API error payload."""
    if isinstance(payload, dict):
        payload_dict = expect_dict(payload, "API error")
        message = payload_dict.get("message")
        if isinstance(message, str) and message.strip():
            return message.strip()

    if isinstance(payload, str) and payload.strip():
        return payload.strip()

    return "GitHub API request failed."


def api_request(
    context: RepoContext,
    *,
    endpoint: str,
    method: str = "GET",
    params: dict[str, Any] | None = None,
    body: dict[str, Any] | list[Any] | None = None,
    accept: str = DEFAULT_ACCEPT,
) -> GitHubApiResponse:
    """Send a GitHub REST API request."""
    query_string = build_query_string(params)
    endpoint_scheme = parse.urlparse(endpoint).scheme.lower()
    url = endpoint if endpoint_scheme in ABSOLUTE_URL_SCHEMES else f"{context.api_base_url}{endpoint}"
    url = f"{url}{query_string}"
    require_https_url(url)

    request_body: bytes | None = None
    headers = {
        "Accept": accept,
        "Authorization": f"Bearer {context.token}",
        "User-Agent": "github-manage-security-alerts-skill",
        "X-GitHub-Api-Version": DEFAULT_API_VERSION,
    }

    json_content_type = "application/json"

    if body is not None:
        request_body = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = json_content_type

    http_request = request.Request(
        url,
        data=request_body,
        headers=headers,
        method=method.upper(),
    )

    try:
        with request.urlopen(http_request) as response:
            response_headers = {key.lower(): value for key, value in response.headers.items()}
            raw_body = response.read()
            content_type = response_headers.get("content-type", "")
            if not raw_body:
                parsed_body: Any = None
            elif json_content_type in content_type or accept == DEFAULT_ACCEPT:
                parsed_body = json.loads(raw_body.decode("utf-8"))
            else:
                parsed_body = raw_body.decode("utf-8")

            return GitHubApiResponse(
                data=parsed_body,
                headers=response_headers,
                status_code=response.status,
                url=url,
            )
    except error.HTTPError as exc:
        try:
            raw_error_body = exc.read()
        finally:
            exc.close()
        content_type = exc.headers.get("Content-Type", "")
        if raw_error_body:
            if json_content_type in content_type:
                response_data = json.loads(raw_error_body.decode("utf-8"))
            else:
                response_data = raw_error_body.decode("utf-8")
        else:
            response_data = None

        raise GitHubApiError(
            endpoint=endpoint,
            message=extract_api_error_message(response_data),
            response_data=response_data,
            status_code=exc.code,
            url=url,
        ) from exc


def safe_api_request(
    context: RepoContext,
    *,
    endpoint: str,
    method: str = "GET",
    params: dict[str, Any] | None = None,
    body: dict[str, Any] | list[Any] | None = None,
    accept: str = DEFAULT_ACCEPT,
) -> dict[str, Any]:
    """Execute an API request and return a structured success/error result."""
    try:
        response = api_request(
            context,
            endpoint=endpoint,
            method=method,
            params=params,
            body=body,
            accept=accept,
        )
    except GitHubApiError as exc:
        return {
            "error": {
                "endpoint": exc.endpoint,
                "message": str(exc),
                "response": exc.response_data,
                "status_code": exc.status_code,
                "url": exc.url,
            },
            "ok": False,
        }

    return {
        "data": response.data,
        "headers": response.headers,
        "ok": True,
        "status_code": response.status_code,
        "url": response.url,
    }
