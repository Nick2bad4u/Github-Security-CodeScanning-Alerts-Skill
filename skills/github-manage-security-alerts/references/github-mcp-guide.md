# GitHub MCP Companion Guide

Use this reference when the user already has GitHub MCP tools available, or when they ask how to combine this skill with GitHub MCP dependency or secret scanning.

This skill's bundled Python helper manages persisted GitHub alert records: code scanning alerts, Dependabot alerts, malware alerts, secret scanning alerts, locations, exports, and state transitions.
GitHub MCP tools can complement it by scanning current content, staged changes, branch dependency changes, or specific packages before those issues become persisted repository alerts.

## Routing

Use the bundled helper when the task is about GitHub alert records:

- summarize current GitHub alert posture
- list, show, export, dismiss, reopen, resolve, or assign alerts
- inspect secret scanning locations or scan history
- inspect repository security settings
- run a raw GitHub security API fallback

Use GitHub MCP tools when the task is about pre-alert scanning or advisory checks:

- scan a pasted snippet, file, or staged diff for secrets
- check new dependency changes before commit or merge
- check one package and version against known advisories
- run an MCP-backed repository dependency scan when the user asks for that workflow

If both apply, use MCP first to inspect current content and use the bundled helper afterward to inspect or update persisted GitHub alerts.

## Setup Assumptions

Do not assume MCP tools are available. First inspect the agent's available tools.

If GitHub MCP is already configured, use the relevant tools directly.
If it is not configured, explain that this guide is optional and continue with the bundled helper for GitHub alert records.
Do not install MCP servers, download CLIs, or change editor/agent configuration unless the user asks for setup help.

When setup help is requested, point users to the GitHub MCP Server and enable only the needed toolsets:

- Dependabot or advisory checks need the Dependabot/dependency security toolset.
- Secret checks need the secret protection or secret scanning toolset.

For non-Copilot clients, authentication may require a `Authorization: Bearer <token>` header or equivalent client-specific token configuration. Keep tokens in environment variables or secret storage, never in repository files.

## Secret Scanning With MCP

Use MCP secret scanning when the user asks to scan content, files, staged changes, or recent diffs for secrets.
This is different from `list-secret-scanning`, which lists alerts already known to GitHub for a repository.

Prefer narrow inputs:

- pasted content from the user
- the specific file the user named
- `git diff --cached` when the user asks to scan staged changes
- a focused branch diff when the user asks to scan recent work

Avoid large generated or vendor directories such as `node_modules/`, build output, compiled assets, and vendored dependencies unless the user explicitly asks to include them.
Do not skip ignored files automatically when the user asks to scan local secret-prone files such as `.env` or local config; confirm scope if including them would expose sensitive local data.

If secrets are detected:

1. Do not echo secret values back to the user.
2. Report file/path, line, secret type, and confidence when available.
3. Recommend removing the secret from code and moving runtime values to environment variables or secret storage.
4. If the secret was committed or pushed, recommend rotation or revocation before resolving any GitHub secret scanning alert.
5. Use this skill's bundled helper only if the user also needs persisted alert inspection or resolution.

## Dependency Scanning With MCP

Use MCP dependency/advisory tools when the user asks to check whether packages or dependency changes are vulnerable before merge.
This is different from `list-dependabot`, which lists existing Dependabot alerts for a repository.

For a specific package:

- identify package name, version, and ecosystem
- call the available MCP dependency vulnerability tool
- report GHSA/CVE identifiers, severity, affected range, patched version, and remediation

For branch changes:

1. Detect changed dependency manifests and lockfiles.
2. Ignore generated/vendor directories unless the user asks otherwise.
3. Parse new or updated dependency names, versions, and ecosystems.
4. Batch checks if the tool supports batching.
5. Prioritize critical and high severity findings, malware, patched direct dependencies, and runtime dependencies.

Common dependency files include:

- npm: `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`
- Python: `requirements.txt`, `Pipfile.lock`, `poetry.lock`, `pyproject.toml`, `setup.py`
- Go: `go.mod`, `go.sum`
- Ruby: `Gemfile`, `Gemfile.lock`
- Rust: `Cargo.toml`, `Cargo.lock`
- Maven/Gradle: `pom.xml`, `build.gradle`, `build.gradle.kts`
- NuGet: `*.csproj`, `packages.config`, `*.deps.json`
- Composer: `composer.json`, `composer.lock`
- Dart: `pubspec.yaml`, `pubspec.lock`
- Swift: `Package.swift`, `Package.resolved`

If vulnerable dependencies are found, recommend a concrete package update when the patched version is known.
Use the bundled helper afterward only when the user wants to inspect existing Dependabot or malware alerts, compare MCP results with GitHub alert state, or update alert records.

## MCP And Alert Record Reconciliation

When MCP scan results and GitHub alert records disagree:

- prefer MCP results for the current local diff or pasted content
- prefer GitHub alert records for persisted repository security state
- check branch/ref, manifest path, package version, and default-branch analysis timing
- remember that GitHub alert disappearance may wait for a new scan, dependency graph update, or secret scanning cycle

Do not dismiss a GitHub alert only because a local MCP scan is clean. First verify that the alert path, package version, branch/ref, or secret location no longer applies.

## Reporting

Keep the report concise and actionable:

- scope scanned
- tool or method used
- findings grouped by severity or secret risk
- exact files, packages, versions, and alert numbers when available
- remediation steps
- whether persisted GitHub alert records still need inspection with the bundled helper

Do not include raw secret values, bearer tokens, Authorization headers, or full sensitive scan payloads in chat, logs, commits, or saved reports.
