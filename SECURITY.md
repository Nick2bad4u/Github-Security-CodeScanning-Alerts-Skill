# Security Policy

## Supported scope

This repository contains automation and helper scripts for GitHub repository security alert triage.

Security-sensitive areas include:

- credential/token handling
- API mutation commands (`update-code-scanning`, `update-dependabot`, `update-secret-scanning`, `bulk-update-alerts`)
- workflow automation that can post comments or update repository state

## Reporting a vulnerability

If you discover a vulnerability, please avoid opening a public issue with exploit details.

Instead, contact the maintainer privately (for example via GitHub security reporting or direct private channel) and include:

1. affected file(s) / workflow(s)
2. reproducible steps
3. impact assessment
4. any suggested mitigation

## Secret handling rules

- Never hardcode GitHub tokens.
- Never include tokens in command arguments.
- Use environment variables (e.g. `GITHUB_TOKEN`, `GH_TOKEN`).
- Prefer secret manager retrieval into environment variables.

PowerShell example:

```powershell
$env:GITHUB_TOKEN = Get-Secret GITHUB_TOKEN -AsPlainText
```

## Operational safety

- Use `--dry-run` for mutation commands before applying changes.
- Verify target repository (`--repo` or `--repository owner/repo`) before running mutations.
- Re-check state after changes (`summary`, list/show alert commands).
