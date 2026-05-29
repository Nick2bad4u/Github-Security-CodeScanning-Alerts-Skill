---
name: "GitHub-Security-Alerts-Skill-Agent-Guidance"
description: "Repository guidance for the GitHub security alerts management skill."
applyTo: "**"
---

# GitHub Security Alerts Skill Guidance

This repository packages the `github-manage-security-alerts` Codex/open-agent skill. Keep changes focused on the root skill payload and the small repository automation needed to publish it.

## Scope

- Treat `SKILL.md` as the user-facing skill entrypoint.
- Treat `scripts/manage_github_security_alerts.py` as the CLI entrypoint.
- Keep helper modules in `scripts/` stdlib-only unless a dependency is explicitly justified and documented.
- Keep `agents/openai.yaml`, `assets/`, and `LICENSE.txt` synchronized with the packaged skill.

## Security

- Never put GitHub tokens in command arguments, docs examples, logs, commits, or chat output.
- Prefer token environment variables such as `GITHUB_TOKEN`, `GH_TOKEN`, or a caller-specified `--token-env`.
- Use `--dry-run` first for bulk updates, dismissals, reopen operations, or alert state transitions.
- Do not dismiss or resolve security alerts unless the vulnerable path, secret exposure, or code scanning result has actually been reviewed.

## Validation

Run the narrowest useful checks after edits:

```powershell
python -m compileall scripts
npm run release:verify
```

For behavior changes, also run the relevant CLI command with `--json` against a safe repository or use `--dry-run` for mutations.

## Style

- Prefer clear argparse surfaces and explicit error messages.
- Keep API response parsing defensive; validate external JSON before indexing nested fields.
- Keep docs examples copy-pasteable in PowerShell.
- Avoid broad repo-template changes unless the task is explicitly about repository automation or packaging.
