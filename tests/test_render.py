"""Tests for text rendering behavior."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from github_security_render import emit_output, render_secret_locations, render_text, render_update_result

if TYPE_CHECKING:
    import pytest


def test_render_text_uses_default_json_renderer_for_unknown_command() -> None:
    """Unknown command renderers fall back to stable JSON output."""
    rendered = render_text("future-command", {"b": 2, "a": 1})

    assert rendered == json.dumps({"b": 2, "a": 1}, indent=2, sort_keys=True)


def test_render_text_handles_malware_payload_envelope() -> None:
    """Malware list rendering unwraps the API payload envelope."""
    rendered = render_text(
        "list-malware",
        [
            {
                "number": 7,
                "state": "open",
                "dependency": {"manifest_path": "package-lock.json"},
                "security_advisory": {"ghsa_id": "GHSA-test"},
                "security_vulnerability": {
                    "package": {"name": "example"},
                    "severity": "critical",
                },
                "html_url": "https://github.com/example/repo/security/dependabot/7",
            },
        ],
    )

    assert "Dependabot malware alerts (1):" in rendered
    assert "package=example" in rendered
    assert "ghsa=GHSA-test malware" in rendered


def test_render_secret_locations_handles_empty_location_list() -> None:
    """Empty secret location payloads get a concise user-facing message."""
    assert render_secret_locations([]) == "No secret locations found."


def test_render_update_result_identifies_dry_run_payload() -> None:
    """Dry-run mutation output is labeled before the JSON body."""
    rendered = render_update_result({"dry_run": True, "alerts": [1]})

    assert rendered.startswith("Dry run:\n")
    assert '"alerts": [' in rendered


def test_emit_output_prints_json_when_requested(capsys: pytest.CaptureFixture[str]) -> None:
    """JSON output mode bypasses human-readable renderers."""
    emit_output({"b": 2, "a": 1}, as_json=True, command="summary")

    captured = capsys.readouterr()
    assert captured.out == '{\n  "a": 1,\n  "b": 2\n}\n'
    assert captured.err == ""
