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


def test_render_summary_includes_counts_samples_and_unavailable_sections() -> None:
    """Summary rendering includes available sections, samples, and API failures."""
    rendered = render_text(
        "summary",
        {
            "api_base_url": "https://api.example.test",
            "full_name": "octo/repo",
            "repository_html_url": "https://github.example.test/octo/repo",
            "sections": {
                "code_scanning": {
                    "counts_by_state": {"open": 1},
                    "ok": True,
                    "sample_alerts": [
                        {
                            "html_url": "https://github.example.test/alert",
                            "most_recent_instance": {"location": {"path": "scripts/app.py"}},
                            "number": 1,
                            "rule": {"id": "py/test", "security_severity_level": "high"},
                            "state": "open",
                        }
                    ],
                    "total": 1,
                },
                "dependabot": {
                    "counts_by_state": {},
                    "ok": True,
                    "sample_alerts": [],
                    "total": 0,
                },
                "malware": {
                    "counts_by_state": {},
                    "lookup_failures": [{"ghsa_id": "GHSA-test"}],
                    "ok": True,
                    "sample_alerts": [],
                    "total": 0,
                },
                "secret_scanning": {
                    "error": {"message": "disabled", "status_code": 404},
                    "ok": False,
                },
            },
            "token_env": "GITHUB_TOKEN",
        },
    )

    assert "Repository: octo/repo" in rendered
    assert "counts: open=1" in rendered
    assert "rule=py/test path=scripts/app.py" in rendered
    assert "malware-type lookup failures: 1" in rendered
    assert "status: unavailable (404) disabled" in rendered


def test_render_alert_lists_cover_surface_specific_briefs() -> None:
    """List renderers include the identifying details for each alert family."""
    code_scanning = render_text(
        "list-code-scanning",
        [
            {
                "html_url": "code-url",
                "number": 2,
                "rule": {"name": "fallback-rule", "severity": "warning"},
                "state": "fixed",
            }
        ],
    )
    dependabot = render_text(
        "list-dependabot",
        [
            {
                "dependency": {"manifest_path": "package-lock.json", "package": {"name": "fallback-pkg"}},
                "html_url": "dep-url",
                "number": 3,
                "security_advisory": {},
                "security_vulnerability": {"severity": "critical"},
                "state": "open",
            }
        ],
    )
    secret_scanning = render_text(
        "list-secret-scanning",
        [
            {
                "html_url": "secret-url",
                "number": 4,
                "publicly_leaked": True,
                "resolution": "revoked",
                "secret_type": "github_token",
                "state": "resolved",
                "validity": "active",
            }
        ],
    )

    assert "rule=fallback-rule path=<unknown-path>" in code_scanning
    assert "package=fallback-pkg manifest=package-lock.json ghsa=unknown-ghsa" in dependabot
    assert "secret_type=github_token resolution=revoked validity=active publicly_leaked=True" in secret_scanning


def test_render_repo_overview_locations_and_malware_lookup_failures(capsys: pytest.CaptureFixture[str]) -> None:
    """Renderer helpers cover object details and malware lookup diagnostics."""
    overview = render_text(
        "repo-security-overview",
        {
            "api_base_url": "https://api.example.test",
            "full_name": "octo/repo",
            "html_url": "https://github.example.test/octo/repo",
            "private": False,
            "security_and_analysis": {"advanced_security": {"status": "enabled"}},
            "visibility": "public",
        },
    )
    locations = render_secret_locations(
        [
            {"details": {"path": "README.md"}, "type": "commit"},
            {"details": "no details", "type": "issue"},
        ],
    )
    emit_output(
        {
            "alerts": [
                {
                    "dependency": {"manifest_path": "requirements.txt"},
                    "html_url": "malware-url",
                    "number": 5,
                    "security_advisory": {"ghsa_id": "GHSA-malware"},
                    "security_vulnerability": {"package": {"name": "bad-lib"}, "severity": "high"},
                    "state": "open",
                }
            ],
            "lookup_failures": [{"ghsa_id": "GHSA-error"}],
        },
        as_json=False,
        command="list-malware",
    )

    captured = capsys.readouterr()
    assert "Visibility: public" in overview
    assert '- commit: {"path": "README.md"}' in locations
    assert "- issue: no details" in locations
    assert "bad-lib" in captured.out
    assert "Malware advisory lookup failures" in captured.out


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
