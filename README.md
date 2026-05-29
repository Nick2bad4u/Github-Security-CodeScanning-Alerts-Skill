# GitHub Security Alerts Skill

[![latest GitHub release.](https://flat.badgen.net/github/release/Nick2bad4u/Github-Security-CodeScanning-Alerts-Skill?color=cyan)](https://github.com/Nick2bad4u/Github-Security-CodeScanning-Alerts-Skill/releases) [![GitHub stars.](https://flat.badgen.net/github/stars/Nick2bad4u/Github-Security-CodeScanning-Alerts-Skill?color=yellow)](https://github.com/Nick2bad4u/Github-Security-CodeScanning-Alerts-Skill/stargazers) [![GitHub forks.](https://flat.badgen.net/github/forks/Nick2bad4u/Github-Security-CodeScanning-Alerts-Skill?color=green)](https://github.com/Nick2bad4u/Github-Security-CodeScanning-Alerts-Skill/forks) [![GitHub open issues.](https://flat.badgen.net/github/open-issues/Nick2bad4u/Github-Security-CodeScanning-Alerts-Skill?color=red)](https://github.com/Nick2bad4u/Github-Security-CodeScanning-Alerts-Skill/issues) [![GitHub PRs.](https://flat.badgen.net/github/open-prs/Nick2bad4u/Github-Security-CodeScanning-Alerts-Skill?color=orange)](https://github.com/Nick2bad4u/Github-Security-CodeScanning-Alerts-Skill/pulls?q=sort%3Aupdated-desc+is%3Apr+is%3Aopen) [![GitHub license](https://flat.badgen.net/github/license/Nick2bad4u/Github-Security-CodeScanning-Alerts-Skill?color=purple)](https://github.com/Nick2bad4u/Github-Security-CodeScanning-Alerts-Skill/blob/main/LICENSE) [![GitHub Dependabot](https://flat.badgen.net/github/dependabot/Nick2bad4u/Github-Security-CodeScanning-Alerts-Skill?color=blue)](https://github.com/Nick2bad4u/Github-Security-CodeScanning-Alerts-Skill/network/updates)

An open-agent skill for inspecting and managing GitHub repository security alerts across:

- code scanning
- Dependabot
- Dependabot malware
- secret scanning

This repository provides:

- a reusable `github-manage-security-alerts` skill (`SKILL.md`)
- a Python CLI helper to inspect and triage alerts
- GitHub automation for release/security hygiene

---

## What this skill can do

With a GitHub token in an environment variable, you can:

- summarize repository alert posture (`summary`)
- export full alert snapshots for bulk triage (`export-alerts`)
- list/show/update code scanning alerts
- list/show/update Dependabot alerts
- list/show/update malware alerts (Dependabot malware subset)
- list/show/update secret scanning alerts
- inspect secret locations and secret scan history
- inspect repository security setup overview
- perform bulk alert updates (`bulk-update-alerts`) with `--dry-run`
- fall back to raw REST calls for unsupported endpoints (`api-call`)

> The helper is repository-agnostic: pass `--repo` to any local checkout, or pass explicit `--repository owner/repo`.

---

## Repository layout

```text
SKILL.md
agents/
  openai.yaml
assets/
  github-manage-security-alerts-small.svg
  github-manage-security-alerts.png
scripts/
  manage_github_security_alerts.py
  github_security_api.py
  github_security_cli.py
  github_security_common.py
  github_security_operations.py
  github_security_render.py
README.md
CONTRIBUTING.md
SECURITY.md
CHANGELOG.md
```

---

## Agent compatibility

This is a root `SKILL.md` package. `npx skills` can install it directly from GitHub, and `npx skills experimental_sync` can discover it from `node_modules` because the npm package ships `SKILL.md` at the package root.

Use `--agent universal` for agents that consume the shared `.agents/skills` layout. Use `--agent "*"` only when you intentionally want to install to every supported agent directory.

```powershell
npx skills add Nick2bad4u/Github-Security-CodeScanning-Alerts-Skill -g --agent universal -y
npx skills add Nick2bad4u/Github-Security-CodeScanning-Alerts-Skill -g --agent "*" -y
npm install --save-dev github-manage-security-alerts-skill
npx skills experimental_sync --agent universal -y
```

OpenAI-specific display metadata lives in `agents/openai.yaml`. The portable skill contract is `SKILL.md` plus the referenced `assets/` and `scripts/` files.

---

## Publishing

The skill is packaged for GitHub releases and npm as `github-manage-security-alerts-skill`.

Verify the package locally before publishing:

```powershell
npm run release:verify
npm publish --access public --provenance
```

GitHub Actions publishes with npm OIDC trusted publishing using `npm publish --access public --provenance`. Configure the npm package trusted publisher for repository `Nick2bad4u/Github-Security-CodeScanning-Alerts-Skill` and workflow `.github/workflows/release-skill.yml`. The workflow intentionally does not use `npm stage` commands.

---

## Quick start

### 1) Prerequisites

- Python 3.10+
- A GitHub token exported to an environment variable (recommended: `GITHUB_TOKEN`)

### 2) Set your token (do not pass it on CLI)

#### PowerShell

```powershell
$env:GITHUB_TOKEN = "<your-token>"
```

#### Bash

```bash
export GITHUB_TOKEN="<your-token>"
```

### 3) Run the helper

From repository root:

```powershell
python "scripts/manage_github_security_alerts.py" summary --repo "."
```

Machine-readable output:

```powershell
python "scripts/manage_github_security_alerts.py" summary --repo "." --json
```

---

## Common commands

```powershell
# Export full alert sets for triage
python "scripts/manage_github_security_alerts.py" export-alerts --repo "." --json

# List open high/error code scanning alerts
python "scripts/manage_github_security_alerts.py" list-code-scanning --repo "." --state open --severity high,error

# Dismiss a code scanning alert (dry-run first)
python "scripts/manage_github_security_alerts.py" update-code-scanning --repo "." --alert 42 --state dismissed --dismissed-reason false_positive --comment "False positive after review." --dry-run

# List open Dependabot alerts
python "scripts/manage_github_security_alerts.py" list-dependabot --repo "." --state open

# List open secret scanning alerts
python "scripts/manage_github_security_alerts.py" list-secret-scanning --repo "." --state open

# Bulk update (preview only)
python "scripts/manage_github_security_alerts.py" bulk-update-alerts --repo "." --surface code-scanning --select-state open --target-state dismissed --dismissed-reason "false positive" --comment "Reviewed and intentionally dismissed." --limit 10 --dry-run --json
```

For the full command surface and workflows, see:

- `SKILL.md`

---

## Security notes

- Never paste tokens into command arguments or commit them to git.
- Prefer environment variables and secret managers.
- Use `--dry-run` before mutation and bulk mutation actions.

More details: [`SECURITY.md`](./SECURITY.md)

---

## Contributing

Contributions are welcome. Please read:

- [`CONTRIBUTING.md`](./CONTRIBUTING.md)
- [`CHANGELOG.md`](./CHANGELOG.md)

---

## Releases and downloads

This repository includes a release workflow that creates a downloadable zip bundle:

- Workflow: `.github/workflows/release-skill.yml`
- Trigger:
	- push a tag like `v0.1.0`
	- run manually via **workflow_dispatch** with:
		- `release_type`: `patch` / `minor` / `major`
		- `version`: optional explicit `x.y.z` (overrides `release_type`)
		- `ref`: branch to release from (default `main`)
- Asset: `github-security-codescanning-alerts-skill-<tag>.zip`

Examples:

```powershell
# Manual patch bump from main
gh workflow run "Release Skill Bundle" -f release_type=patch -f ref=main

# Manual explicit release version
gh workflow run "Release Skill Bundle" -f release_type=patch -f version=0.2.0 -f ref=main
```

---

## License

Released under [The Unlicense](./LICENSE).
