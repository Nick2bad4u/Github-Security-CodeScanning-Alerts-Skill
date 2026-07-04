"""Text and JSON rendering for GitHub security alert command output."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from github_security_common import expect_dict

Renderer = Callable[[Any], str]


def render_text(command: str, payload: Any) -> str:
    """Render command output as human-readable text."""
    renderers: dict[str, Renderer] = {
        "summary": render_summary,
        "repo-security-overview": render_repo_security_overview,
        "bulk-update-alerts": render_json_like,
        "list-code-scanning": render_code_scanning_list,
        "show-code-scanning": render_json_like,
        "update-code-scanning": render_update_result,
        "list-dependabot": render_dependabot_list,
        "show-dependabot": render_json_like,
        "update-dependabot": render_update_result,
        "show-malware": render_json_like,
        "update-malware": render_update_result,
        "list-secret-scanning": render_secret_scanning_list,
        "show-secret-scanning": render_json_like,
        "update-secret-scanning": render_update_result,
        "list-secret-locations": render_secret_locations,
        "secret-scan-history": render_json_like,
        "export-alerts": render_json_like,
        "api-call": render_json_like,
    }
    if command == "list-malware":
        return render_dependabot_list(payload, heading="Dependabot malware alerts", kind="malware")

    return renderers.get(command, render_json_like)(payload)


def emit_output(payload: Any, *, as_json: bool, command: str) -> None:
    """Print output in JSON or text form."""
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return

    text_payload: Any = payload
    payload_dict: dict[str, Any] | None = None
    if command == "list-malware" and isinstance(payload, dict):
        payload_dict = expect_dict(payload, "malware alert list")
        text_payload = payload_dict.get("alerts", [])
    print(render_text(command, text_payload))
    lookup_failures = payload_dict.get("lookup_failures") if payload_dict is not None else None
    if lookup_failures:
        print("\nMalware advisory lookup failures:")
        print(json.dumps(lookup_failures, indent=2, sort_keys=True))


def render_summary(payload: dict[str, Any]) -> str:
    """Render a repository security summary."""
    lines = [
        f"Repository: {payload['full_name']}",
        f"Repository URL: {payload['repository_html_url']}",
        f"API base URL: {payload['api_base_url']}",
        f"Token environment variable: {payload['token_env']}",
        "",
        "Sections:",
    ]

    for section_name in (
        "code_scanning",
        "dependabot",
        "malware",
        "secret_scanning",
    ):
        append_summary_section(lines, section_name, payload["sections"][section_name])

    return "\n".join(lines)


def append_summary_section(lines: list[str], section_name: str, section: dict[str, Any]) -> None:
    lines.append(f"- {section_name.replace('_', ' ')}:")
    if not section.get("ok"):
        append_unavailable_section(lines, section)
        return

    lines.append(f"  total: {section.get('total', 0)}")
    append_counts(lines, section.get("counts_by_state", {}))
    append_sample_alerts(lines, section_name, section.get("sample_alerts", []))
    lookup_failures = section.get("lookup_failures")
    if lookup_failures:
        lines.append(f"  malware-type lookup failures: {len(lookup_failures)}")


def append_unavailable_section(lines: list[str], section: dict[str, Any]) -> None:
    error_payload = section.get("error", {})
    message = (
        f"  status: unavailable ({error_payload.get('status_code', 'n/a')}) "
        f"{error_payload.get('message', 'unknown error')}"
    )
    lines.append(message)


def append_counts(lines: list[str], counts: Any) -> None:
    if not counts:
        return
    lines.append("  counts: " + ", ".join(f"{state}={count}" for state, count in sorted(counts.items())))


def append_sample_alerts(lines: list[str], section_name: str, samples: Any) -> None:
    if not samples:
        return

    lines.append("  samples:")
    lines.extend(f"    - {render_alert_brief(alert, section_name)}" for alert in samples)


def render_repo_security_overview(payload: dict[str, Any]) -> str:
    """Render repository settings overview."""
    lines = [
        f"Repository: {payload['full_name']}",
        f"Repository URL: {payload.get('html_url')}",
        f"Visibility: {payload.get('visibility')}",
        f"Private: {payload.get('private')}",
        f"API base URL: {payload['api_base_url']}",
        "",
        "security_and_analysis:",
        json.dumps(payload.get("security_and_analysis"), indent=2, sort_keys=True),
    ]
    return "\n".join(lines)


def render_code_scanning_list(alerts: list[dict[str, Any]]) -> str:
    """Render code scanning alerts as lines of text."""
    return render_alert_list(alerts, heading="Code scanning alerts", kind="code_scanning")


def render_dependabot_list(
    alerts: list[dict[str, Any]],
    *,
    heading: str = "Dependabot alerts",
    kind: str = "dependabot",
) -> str:
    """Render Dependabot alerts as lines of text."""
    return render_alert_list(alerts, heading=heading, kind=kind)


def render_secret_scanning_list(alerts: list[dict[str, Any]]) -> str:
    """Render secret scanning alerts as lines of text."""
    return render_alert_list(alerts, heading="Secret scanning alerts", kind="secret_scanning")


def render_secret_locations(locations: list[dict[str, Any]]) -> str:
    """Render secret scanning locations."""
    if not locations:
        return "No secret locations found."

    lines = ["Secret scanning alert locations:"]
    for location in locations:
        location_type = location.get("type", "unknown")
        details = location.get("details")
        if isinstance(details, dict):
            lines.append(f"- {location_type}: {json.dumps(details, sort_keys=True)}")
        else:
            lines.append(f"- {location_type}: {details}")

    return "\n".join(lines)


def render_alert_list(alerts: list[dict[str, Any]], *, heading: str, kind: str) -> str:
    """Render a generic alert list with one alert per line."""
    if not alerts:
        return f"{heading}: none"

    lines = [f"{heading} ({len(alerts)}):"]
    lines.extend(f"- {render_alert_brief(alert, kind)}" for alert in alerts)
    return "\n".join(lines)


def render_alert_brief(alert: dict[str, Any], kind: str) -> str:
    """Create a one-line summary for one alert."""
    number = alert.get("number", "?")
    state = alert.get("state", "unknown")
    html_url = alert.get("html_url")

    if kind == "code_scanning":
        return render_code_scanning_brief(alert, number, state, html_url)

    if kind in {"dependabot", "malware"}:
        return render_dependabot_brief(alert, kind, number, state, html_url)

    if kind == "secret_scanning":
        return render_secret_scanning_brief(alert, number, state, html_url)

    return f"#{number} [{state}] url={html_url}"


def render_code_scanning_brief(alert: dict[str, Any], number: Any, state: Any, html_url: Any) -> str:
    rule = optional_dict(alert.get("rule"), "code scanning rule")
    instance = optional_dict(alert.get("most_recent_instance"), "code scanning instance")
    location = optional_dict(instance.get("location"), "code scanning location")
    severity = rule.get("security_severity_level") or rule.get("severity") or "unknown"
    rule_name = rule.get("id") or rule.get("name") or "unknown-rule"
    path = location.get("path") or "<unknown-path>"
    return f"#{number} [{state}] severity={severity} rule={rule_name} path={path} url={html_url}"


def render_dependabot_brief(alert: dict[str, Any], kind: str, number: Any, state: Any, html_url: Any) -> str:
    vulnerability = optional_dict(alert.get("security_vulnerability"), "Dependabot vulnerability")
    package = optional_dict(vulnerability.get("package"), "Dependabot package")
    dependency = optional_dict(alert.get("dependency"), "Dependabot dependency")
    severity = vulnerability.get("severity") or alert.get("state") or "unknown"
    package_name = resolve_package_name(package, dependency)
    manifest_path = dependency.get("manifest_path") or "<unknown-manifest>"
    ghsa_id = resolve_ghsa_id(alert)
    malware_suffix = " malware" if kind == "malware" else ""
    return (
        f"#{number} [{state}] severity={severity} package={package_name} "
        f"manifest={manifest_path} ghsa={ghsa_id}{malware_suffix} url={html_url}"
    )


def render_secret_scanning_brief(alert: dict[str, Any], number: Any, state: Any, html_url: Any) -> str:
    secret_type = alert.get("secret_type") or "unknown-secret-type"
    resolution = alert.get("resolution") or "unresolved"
    validity = alert.get("validity") or "unknown"
    leaked = alert.get("publicly_leaked")
    return (
        f"#{number} [{state}] secret_type={secret_type} resolution={resolution} "
        f"validity={validity} publicly_leaked={leaked} url={html_url}"
    )


def optional_dict(value: Any, label: str) -> dict[str, Any]:
    if value is None:
        return {}
    return expect_dict(value or {}, label)


def resolve_package_name(package: dict[str, Any], dependency: dict[str, Any]) -> str | None:
    package_name = package.get("name")
    if isinstance(package_name, str):
        return package_name

    dependency_package = dependency.get("package")
    if isinstance(dependency_package, dict):
        dependency_payload = expect_dict(dependency_package, "dependency package")
        dependency_package_name = dependency_payload.get("name")
        if isinstance(dependency_package_name, str):
            return dependency_package_name

    return None


def resolve_ghsa_id(alert: dict[str, Any]) -> str:
    advisory = alert.get("security_advisory")
    if isinstance(advisory, dict):
        advisory_payload = expect_dict(advisory, "security advisory")
        ghsa_id = advisory_payload.get("ghsa_id")
        if isinstance(ghsa_id, str) and ghsa_id:
            return ghsa_id
    return "unknown-ghsa"


def render_update_result(payload: dict[str, Any]) -> str:
    """Render dry-run or mutation results."""
    if payload.get("dry_run"):
        return "Dry run:\n" + json.dumps(payload, indent=2, sort_keys=True)

    return json.dumps(payload, indent=2, sort_keys=True)


def render_json_like(payload: Any) -> str:
    """Render arbitrary payloads as pretty JSON."""
    return json.dumps(payload, indent=2, sort_keys=True)
