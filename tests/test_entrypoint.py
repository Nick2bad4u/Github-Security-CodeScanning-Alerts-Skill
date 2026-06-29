"""Tests for the executable CLI entry point."""
# pyright: reportUnknownLambdaType=false

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import github_security_api
import github_security_cli
import github_security_operations
import github_security_render
import manage_github_security_alerts
from github_security_common import GitHubSecurityCliError


def namespace(**values: object) -> Any:
    """Build a dynamic argparse-like namespace."""
    return SimpleNamespace(**values)


def test_main_resolves_context_handles_command_and_emits_output(monkeypatch: Any) -> None:
    """The entry point wires parser, context resolution, command handling, and rendering."""
    calls: list[str] = []
    arguments = namespace(command="summary", json=False)

    monkeypatch.setattr(github_security_cli, "parse_args", lambda: arguments)
    monkeypatch.setattr(github_security_api, "resolve_context", lambda _arguments: "context")
    monkeypatch.setattr(github_security_operations, "handle_command", lambda _context, _arguments: {"ok": True})

    def fake_emit_output(payload: object, *, as_json: bool, command: str) -> None:
        calls.append(f"{command}:{as_json}:{payload}")

    monkeypatch.setattr(github_security_render, "emit_output", fake_emit_output)

    assert manage_github_security_alerts.main() == 0
    assert calls == ["summary:False:{'ok': True}"]


def test_main_prints_text_errors(monkeypatch: Any, capsys: Any) -> None:
    """Human-readable mode prints concise errors to stderr."""
    arguments = namespace(command="summary", json=False)

    monkeypatch.setattr(github_security_cli, "parse_args", lambda: arguments)
    monkeypatch.setattr(
        github_security_api,
        "resolve_context",
        lambda _arguments: (_ for _ in ()).throw(GitHubSecurityCliError("missing token")),
    )

    assert manage_github_security_alerts.main() == 1
    captured = capsys.readouterr()
    assert captured.err == "Error: missing token\n"


def test_main_prints_json_errors(monkeypatch: Any, capsys: Any) -> None:
    """JSON mode emits structured error payloads to stderr."""
    arguments = namespace(command="api-call", json=True)

    monkeypatch.setattr(github_security_cli, "parse_args", lambda: arguments)
    monkeypatch.setattr(github_security_api, "resolve_context", lambda _arguments: "context")
    monkeypatch.setattr(
        github_security_operations,
        "handle_command",
        lambda _context, _arguments: (_ for _ in ()).throw(GitHubSecurityCliError("bad endpoint")),
    )

    assert manage_github_security_alerts.main() == 1
    captured = capsys.readouterr()
    assert '"command": "api-call"' in captured.err
    assert '"message": "bad endpoint"' in captured.err
