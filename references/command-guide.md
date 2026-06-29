# GitHub Security Alerts Command Guide

Use this reference after loading `SKILL.md` when you need command-specific syntax.

All authenticated examples assume a GitHub token is already available through `GITHUB_TOKEN`, `GH_TOKEN`, or a variable passed with `--token-env`.
Global options can appear before or after the subcommand; examples use the command-first style.

## Global Options

- `--repo`: path inside the target repository checkout, default `.`.
- `--repository`: explicit repository in `owner/repo` format or a GitHub repository URL.
- `--api-base-url`: explicit GitHub API base URL override.
- `--web-base-url`: explicit GitHub web base URL override for rendered links.
- `--token-env`: token environment variable name. Repeat for fallbacks.
- `--json`: emit machine-readable JSON.

## Inspection

Start with broad read-only commands:

```powershell
python "<path-to-skill>/scripts/manage_github_security_alerts.py" summary --repo "."
python "<path-to-skill>/scripts/manage_github_security_alerts.py" summary --repo "." --sample-size 5 --per-page 100 --json
python "<path-to-skill>/scripts/manage_github_security_alerts.py" repo-security-overview --repo "." --json
python "<path-to-skill>/scripts/manage_github_security_alerts.py" export-alerts --repo "." --json
```

`export-alerts` accepts surface-specific state filters:

```powershell
python "<path-to-skill>/scripts/manage_github_security_alerts.py" export-alerts --repo "." --code-scanning-state open --dependabot-state open --secret-scanning-state open --per-page 100 --json
```

Do not add `--show-secret-values` to exports unless the user explicitly confirms that unredacted secret values are necessary.

## Code Scanning

List and inspect code scanning alerts:

```powershell
python "<path-to-skill>/scripts/manage_github_security_alerts.py" list-code-scanning --repo "." --state open --severity high,error --per-page 100 --json
python "<path-to-skill>/scripts/manage_github_security_alerts.py" list-code-scanning --repo "." --tool-name CodeQL --state open
python "<path-to-skill>/scripts/manage_github_security_alerts.py" list-code-scanning --repo "." --ref refs/heads/main --pr 123
python "<path-to-skill>/scripts/manage_github_security_alerts.py" show-code-scanning --repo "." --alert 42 --include-instances --include-autofix --json
```

Common filters include `--state`, `--severity`, `--tool-name`, `--tool-guid`, `--assignees`, `--ref`, `--pr`, `--sort`, `--direction`, `--page`, and `--per-page`.

Dismiss, reopen, assign, or request dismissal for one alert:

```powershell
python "<path-to-skill>/scripts/manage_github_security_alerts.py" update-code-scanning --repo "." --alert 42 --state dismissed --dismissed-reason "false positive" --comment "False positive after manual review." --dry-run
python "<path-to-skill>/scripts/manage_github_security_alerts.py" update-code-scanning --repo "." --alert 42 --state dismissed --dismissed-reason "used in tests" --create-request --dry-run
python "<path-to-skill>/scripts/manage_github_security_alerts.py" update-code-scanning --repo "." --alert 42 --state open
python "<path-to-skill>/scripts/manage_github_security_alerts.py" update-code-scanning --repo "." --alert 42 --state open --assignee octocat --dry-run
```

Allowed code scanning dismissal reasons are `false positive`, `won't fix`, and `used in tests`.

## Dependabot

List and inspect Dependabot alerts:

```powershell
python "<path-to-skill>/scripts/manage_github_security_alerts.py" list-dependabot --repo "." --state open --severity critical,high --has patch --json
python "<path-to-skill>/scripts/manage_github_security_alerts.py" list-dependabot --repo "." --ecosystem npm --package esbuild --manifest package-lock.json
python "<path-to-skill>/scripts/manage_github_security_alerts.py" list-dependabot --repo "." --scope runtime --epss-percentage ">=0.5"
python "<path-to-skill>/scripts/manage_github_security_alerts.py" show-dependabot --repo "." --alert 7 --json
```

Common filters include `--state`, `--severity`, `--ecosystem`, `--package`, `--manifest`, `--epss-percentage`, `--has`, `--assignee`, `--scope`, `--sort`, `--direction`, `--before`, `--after`, and `--per-page`.

Dismiss or reopen a Dependabot alert:

```powershell
python "<path-to-skill>/scripts/manage_github_security_alerts.py" update-dependabot --repo "." --alert 7 --state dismissed --dismissed-reason tolerable_risk --comment "Accepted until the next dependency refresh." --dry-run
python "<path-to-skill>/scripts/manage_github_security_alerts.py" update-dependabot --repo "." --alert 7 --state dismissed --dismissed-reason not_used --comment "Vulnerable package is not reachable in this project." --dry-run
python "<path-to-skill>/scripts/manage_github_security_alerts.py" update-dependabot --repo "." --alert 7 --state open
```

Allowed Dependabot dismissal reasons are `fix_started`, `inaccurate`, `no_bandwidth`, `not_used`, and `tolerable_risk`.

## Malware

Malware commands are backed by Dependabot alert APIs plus GitHub Advisory Database classification:

```powershell
python "<path-to-skill>/scripts/manage_github_security_alerts.py" list-malware --repo "." --state open --json
python "<path-to-skill>/scripts/manage_github_security_alerts.py" list-malware --repo "." --ecosystem npm --package suspicious-package
python "<path-to-skill>/scripts/manage_github_security_alerts.py" show-malware --repo "." --alert 12 --json
```

Update malware alerts only after validating that the Dependabot alert maps to a malware advisory:

```powershell
python "<path-to-skill>/scripts/manage_github_security_alerts.py" update-malware --repo "." --alert 12 --state dismissed --dismissed-reason inaccurate --comment "Reviewed advisory classification and package is not present in the deployed artifact." --dry-run
python "<path-to-skill>/scripts/manage_github_security_alerts.py" update-malware --repo "." --alert 12 --state open
```

Use `--skip-malware-check` only when advisory lookup is unavailable and the user has already confirmed the alert identity.

## Secret Scanning

Secret values are redacted by default. Keep that default unless the user explicitly confirms that unredacted output is necessary.

List and inspect secret scanning alerts:

```powershell
python "<path-to-skill>/scripts/manage_github_security_alerts.py" list-secret-scanning --repo "." --state open --validity active --json
python "<path-to-skill>/scripts/manage_github_security_alerts.py" list-secret-scanning --repo "." --state open --is-publicly-leaked
python "<path-to-skill>/scripts/manage_github_security_alerts.py" list-secret-scanning --repo "." --secret-type github_personal_access_token --is-multi-repo
python "<path-to-skill>/scripts/manage_github_security_alerts.py" show-secret-scanning --repo "." --alert 11 --json
python "<path-to-skill>/scripts/manage_github_security_alerts.py" list-secret-locations --repo "." --alert 11 --per-page 100 --json
python "<path-to-skill>/scripts/manage_github_security_alerts.py" secret-scan-history --repo "." --json
```

Common filters include `--state`, `--secret-type`, `--resolution`, `--assignee`, `--validity`, `--is-publicly-leaked`, `--is-multi-repo`, `--sort`, `--direction`, `--page`, and `--per-page`.

Resolve, reopen, assign, or unassign a secret scanning alert:

```powershell
python "<path-to-skill>/scripts/manage_github_security_alerts.py" update-secret-scanning --repo "." --alert 11 --state resolved --resolution revoked --comment "Credential revoked and rotated." --dry-run
python "<path-to-skill>/scripts/manage_github_security_alerts.py" update-secret-scanning --repo "." --alert 11 --state resolved --resolution used_in_tests --comment "Confirmed non-production test fixture." --dry-run
python "<path-to-skill>/scripts/manage_github_security_alerts.py" update-secret-scanning --repo "." --alert 11 --state open
python "<path-to-skill>/scripts/manage_github_security_alerts.py" update-secret-scanning --repo "." --alert 11 --state open --assignee octocat --dry-run
```

Allowed secret scanning resolutions are `false_positive`, `wont_fix`, `revoked`, `pattern_edited`, `pattern_deleted`, and `used_in_tests`.

## Bulk Updates

Bulk updates can affect multiple alerts. Use `--dry-run`, a narrow selector, and an explicit `--limit` first.

```powershell
python "<path-to-skill>/scripts/manage_github_security_alerts.py" bulk-update-alerts --repo "." --surface code-scanning --select-state open --severity high,error --target-state dismissed --dismissed-reason "false positive" --comment "Reviewed and intentionally dismissed." --limit 10 --dry-run --json

python "<path-to-skill>/scripts/manage_github_security_alerts.py" bulk-update-alerts --repo "." --surface dependabot --select-state open --severity low --has patch --target-state dismissed --dismissed-reason tolerable_risk --comment "Accepted until the next dependency refresh." --limit 25 --dry-run --json

python "<path-to-skill>/scripts/manage_github_security_alerts.py" bulk-update-alerts --repo "." --surface secret-scanning --select-state open --validity inactive --target-state resolved --resolution revoked --comment "Credential revoked before resolution." --limit 25 --dry-run --json
```

Prefer explicit alert numbers when the set has already been reviewed:

```powershell
python "<path-to-skill>/scripts/manage_github_security_alerts.py" bulk-update-alerts --repo "." --surface code-scanning --alert 42 --alert 43 --target-state open --dry-run --json
```

Bulk selection supports surface-specific filters:

- code scanning: `--severity`, `--assignee-filter`, `--tool-name`, `--tool-guid`, `--ref`, `--pr`, `--page`, `--per-page`
- Dependabot and malware: `--severity`, `--assignee-filter`, `--ecosystem`, `--package`, `--manifest`, `--epss-percentage`, `--has`, `--scope`, `--before`, `--after`, `--per-page`
- secret scanning: `--assignee-filter`, `--secret-type`, `--resolution-filter`, `--validity`, `--is-publicly-leaked`, `--is-multi-repo`, `--page`, `--per-page`

## Raw API Fallback

Prefer wrapped commands when available. Use `api-call` for gaps, with relative endpoints when possible.

```powershell
python "<path-to-skill>/scripts/manage_github_security_alerts.py" api-call --repo "." --endpoint /repos/OWNER/REPO/code-scanning/default-setup --json
python "<path-to-skill>/scripts/manage_github_security_alerts.py" api-call --repo "." --endpoint /repos/OWNER/REPO/dependabot/alerts --query-param state=open --json
python "<path-to-skill>/scripts/manage_github_security_alerts.py" api-call --repo "." --method PATCH --endpoint /repos/OWNER/REPO/code-scanning/alerts/42 --body-json '{"state":"dismissed","dismissed_reason":"false positive"}' --json
```

Raw API calls can expose unsupported behavior and bypass helper-specific safety checks. For non-GET requests, show the intended method, endpoint, query params, and body to the user before sending the request.
