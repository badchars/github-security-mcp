<p align="center">
  <br>
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/badchars/github-security-mcp/main/.github/banner-dark.svg">
    <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/badchars/github-security-mcp/main/.github/banner-light.svg">
    <img alt="github-security-mcp" src="https://raw.githubusercontent.com/badchars/github-security-mcp/main/.github/banner-dark.svg" width="700">
  </picture>
</p>

<h3 align="center">GitHub security posture analysis for AI agents.</h3>

<p align="center">
  GitHub Enterprise security features cost $21/user/month.<br>
  This gives your AI agent <b>the same visibility for free</b> — org, repos, Actions, secrets, supply chain.
</p>

<br>

<p align="center">
  <a href="#the-problem">The Problem</a> &bull;
  <a href="#how-its-different">How It's Different</a> &bull;
  <a href="#quick-start">Quick Start</a> &bull;
  <a href="#what-the-ai-can-do">What The AI Can Do</a> &bull;
  <a href="#tools-reference-39-tools">Tools</a> &bull;
  <a href="#check-registry-45-checks">Checks</a> &bull;
  <a href="#architecture">Architecture</a>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License"></a>
  <img src="https://img.shields.io/badge/runtime-Bun-f472b6" alt="Bun">
  <img src="https://img.shields.io/badge/protocol-MCP-8b5cf6" alt="MCP">
  <img src="https://img.shields.io/badge/tools-39-22c55e" alt="39 Tools">
  <img src="https://img.shields.io/badge/checks-45-ef4444" alt="45 Checks">
  <img src="https://img.shields.io/badge/categories-6-f59e0b" alt="6 Categories">
</p>

---

## The Problem

GitHub security is fragmented. You need separate tools for org settings, repo configurations, Actions workflow analysis, secret scanning, supply chain, and access control. No single tool covers it all, and none work with AI agents.

```
Traditional workflow:
  manually check org settings                →  click through 15 pages
  run github-advisory-db for each repo       →  one at a time
  grep workflows for script injection        →  miss half the patterns
  review collaborator access                 →  spreadsheet hell
  check secret scanning alerts               →  another dashboard
  ──────────────────────────────────────────
  Total: hours of manual work per org
```

**github-security-mcp** gives your AI agent 39 tools and 45 security checks via the [Model Context Protocol](https://modelcontextprotocol.io). The agent calls GitHub APIs directly, understands what it finds, and tells you exactly what to fix.

```
With github-security-mcp:
  You: "Audit my GitHub org for security issues and prioritize the fixes"

  Agent: → checks org settings (2FA, SSO, member privileges)
         → scans repos (branch protection, secret scanning, Dependabot)
         → analyzes workflows (script injection, unpinned actions, OIDC)
         → reviews access (teams, collaborators, PATs, GitHub Apps)
         → "12 critical, 8 high — here are the top 5 to fix now"
```

---

## How It's Different

Existing tools focus on one slice of GitHub security. github-security-mcp covers the full stack and works with any AI agent.

<table>
<thead>
<tr>
<th></th>
<th>Existing Tools</th>
<th>github-security-mcp</th>
</tr>
</thead>
<tbody>
<tr>
<td><b>Interface</b></td>
<td>CLI / GitHub UI / dashboards</td>
<td>MCP &mdash; AI agent calls tools in real-time</td>
</tr>
<tr>
<td><b>Scope</b></td>
<td>Single domain (Actions, or secrets, or repos)</td>
<td>Full stack: org + repos + Actions + secrets + supply chain + access</td>
</tr>
<tr>
<td><b>Correlation</b></td>
<td>None &mdash; isolated findings</td>
<td>Agent chains: "This unpinned action + write permissions + no environment protection = supply chain risk"</td>
</tr>
<tr>
<td><b>Remediation</b></td>
<td>Generic docs links</td>
<td>Agent generates specific fix instructions for your exact configuration</td>
</tr>
<tr>
<td><b>Actions analysis</b></td>
<td>Most tools skip workflows</td>
<td>8 checks: script injection, PR target, OIDC, pinning, secrets, runners, environments, permissions</td>
</tr>
<tr>
<td><b>Enterprise features</b></td>
<td>Require GitHub Enterprise ($21/user/mo)</td>
<td>Free &mdash; uses public API with graceful degradation for Enterprise-only features</td>
</tr>
</tbody>
</table>

<br>

<details>
<summary>Specific comparisons with popular tools</summary>

<br>

| Tool | What it does | What it can't do |
|---|---|---|
| [Allstar](https://github.com/ossf/allstar) | Enforce repo settings via GitHub App | No Actions analysis, no secret scanning, no access audit |
| [Scorecard](https://github.com/ossf/scorecard) | OpenSSF security score for repos | Single-repo focus, no org-level checks, no real-time interaction |
| [Legitify](https://github.com/Legit-Labs/legitify) | Org + repo policy enforcement | CLI output, no AI integration, limited Actions analysis |
| [step-security/harden-runner](https://github.com/step-security/harden-runner) | Runtime Actions security | Only Actions, no org/repo/access checks |
| [GitGuardian](https://www.gitguardian.com/) | Secret detection in commits | SaaS only, no self-hosted, limited to secrets domain |
| [Socket](https://socket.dev/) | Supply chain risk analysis | Package-focused, no org/Actions/access analysis |

All of these are excellent tools. github-security-mcp doesn't replace them &mdash; it fills the gap of giving an AI agent **unified, interactive access** across all GitHub security domains.

</details>

---

## Quick Start

### Install

```bash
git clone https://github.com/badchars/github-security-mcp.git
cd github-security-mcp
bun install
```

### Set up authentication

```bash
# Classic PAT (requires: repo, admin:org, admin:org_hook, admin:repo_hook)
export GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

# Fine-grained PAT (preferred — least privilege)
# Organization: Members (read), Administration (read)
# Repository: Administration, Code scanning, Dependabot, Secret scanning,
#             Actions, Environments, Webhooks (all read-only)
```

### Connect to your AI agent

<details open>
<summary><b>Claude Code</b></summary>

```bash
claude mcp add github-security -- bun run /path/to/github-security-mcp/src/index.ts
```

</details>

<details>
<summary><b>Claude Desktop</b></summary>

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "github-security": {
      "command": "bun",
      "args": ["run", "/path/to/github-security-mcp/src/index.ts"],
      "env": {
        "GITHUB_TOKEN": "ghp_your_token_here"
      }
    }
  }
}
```

</details>

<details>
<summary><b>Cursor / Windsurf / other MCP clients</b></summary>

Same JSON config format. Point the command to your installation path.

</details>

### Start auditing

```
You: "Audit my GitHub org for security misconfigurations"
```

That's it. The agent handles the rest.

---

## What The AI Can Do

### Full Organization Audit

```
You: "Run a complete security audit on our GitHub org"

Agent: → github_run_all {org: "myorg", repo: "main-app"}
       → 45 checks across 6 categories
       → github_audit_report
       → "34 findings: 4 critical, 7 high, 12 medium.
          Critical #1: No branch protection on main (REPO-001)
          Critical #2: Script injection in deploy.yml (ACT-001)
          Critical #3: 3 critical Dependabot alerts unfixed 90+ days (REPO-007)
          Critical #4: Unresolved secret scanning alerts (SEC-002)
          Here are the exact fixes for each..."
```

### Actions Workflow Security

```
You: "Check our CI/CD workflows for supply chain risks"

Agent: → github_check_workflow_injection
         Found ${{ github.event.issue.title }} in run: block (deploy.yml:47)
       → github_check_workflow_pinning
         12 actions use tags instead of SHA pins
       → github_check_workflow_pr_target
         build.yml uses pull_request_target with checkout — critical risk
       → github_check_workflow_permissions
         Default GITHUB_TOKEN has write-all permissions
       → "4 supply chain risks found. The PR target + checkout pattern
          allows any fork to execute arbitrary code with write access
          to your repo. Fix this first."
```

### Access Control Review

```
You: "Who has too much access to our repositories?"

Agent: → github_check_team_permissions
         "platform" team has admin on 47 repos, only 3 members
       → github_check_collaborators
         8 outside collaborators with write access
       → github_check_app_permissions
         "old-ci-bot" GitHub App has admin + all repos
       → github_check_pat_usage
         14 classic PATs with repo scope (should be fine-grained)
       → "Reduce blast radius: restrict platform team to maintain,
          remove 3 stale outside collaborators, limit old-ci-bot
          to specific repos, migrate classic PATs to fine-grained."
```

### Secret Exposure Detection

```
You: "Are we properly protecting secrets across our repos?"

Agent: → github_check_secret_scanning
         Secret scanning disabled on 5 private repos
       → github_check_push_protection
         3 push protection bypasses in the last month
       → github_check_secret_patterns
         No custom secret patterns defined
       → github_check_secret_scoping
         2 org secrets available to all repos (should be scoped)
       → "Enable secret scanning on all repos, review the 3 bypasses,
          add custom patterns for internal API keys, and scope
          org secrets to only the repos that need them."
```

---

## Tools Reference (39 tools)

<details>
<summary><b>Organization (7)</b></summary>

| Tool | Description |
|------|-------------|
| `github_check_org_security` | 2FA enforcement, default repo visibility, member creation privileges |
| `github_check_org_sso` | SSO/SAML configuration via GraphQL |
| `github_check_org_members` | Outside collaborators, stale member detection |
| `github_check_org_apps` | OAuth credential authorizations, GitHub App installation permissions |
| `github_check_org_webhooks` | Insecure webhook URLs (HTTP, no secret) |
| `github_check_org_audit_log` | Suspicious audit log activity (Enterprise) |
| `github_list_org_repos` | List all repos in an org with security metadata |

</details>

<details>
<summary><b>Repository (8)</b></summary>

| Tool | Description |
|------|-------------|
| `github_check_repo_branch_protection` | Branch protection rules on default branch |
| `github_check_repo_secrets` | Secret scanning and push protection enablement |
| `github_check_repo_code_scanning` | CodeQL / code scanning enabled, open alerts |
| `github_check_repo_dependabot` | Dependabot enabled, critical alert triage |
| `github_check_repo_settings` | SECURITY.md, private vulnerability reporting, fork restrictions |
| `github_check_repo_webhooks` | Insecure repo-level webhook URLs |
| `github_check_repo_deploy_keys` | Deploy key permissions (read-only vs read-write) |
| `github_check_repo_codeowners` | CODEOWNERS file presence and enforcement |

</details>

<details>
<summary><b>Actions (8)</b></summary>

| Tool | Description |
|------|-------------|
| `github_check_workflow_injection` | Script injection via `${{ github.event.* }}` in `run:` blocks |
| `github_check_workflow_pr_target` | `pull_request_target` + checkout pattern (critical) |
| `github_check_workflow_permissions` | GITHUB_TOKEN default permission scope |
| `github_check_workflow_pinning` | Unpinned third-party actions (tag vs SHA) |
| `github_check_workflow_runners` | Self-hosted runner exposure |
| `github_check_workflow_environments` | Missing environment protection rules |
| `github_check_workflow_secrets` | Secret exfiltration patterns in workflows |
| `github_check_workflow_oidc` | OIDC subject claim customization |

</details>

<details>
<summary><b>Secrets (4)</b></summary>

| Tool | Description |
|------|-------------|
| `github_check_secret_scanning` | Coverage gaps and unresolved alerts |
| `github_check_push_protection` | Push protection bypass tracking |
| `github_check_secret_patterns` | Custom secret pattern configuration |
| `github_check_secret_scoping` | Environment, repo, and org-level secret scoping |

</details>

<details>
<summary><b>Supply Chain (4)</b></summary>

| Tool | Description |
|------|-------------|
| `github_check_dependency_graph` | Dependency graph enablement |
| `github_check_dependabot_updates` | Dependabot security updates configuration |
| `github_check_sbom` | SBOM generation capability |
| `github_check_vulnerabilities` | Known vulnerabilities, critical unfixed > 90 days |

</details>

<details>
<summary><b>Access Control (4)</b></summary>

| Tool | Description |
|------|-------------|
| `github_check_team_permissions` | Team permission levels across repos |
| `github_check_collaborators` | External collaborator access audit |
| `github_check_app_permissions` | GitHub App permission scope review |
| `github_check_pat_usage` | Classic vs fine-grained PAT usage |

</details>

<details>
<summary><b>Meta (4)</b></summary>

| Tool | Description |
|------|-------------|
| `github_list_checks` | Browse all 45 checks, filter by category/severity |
| `github_audit_summary` | Aggregate findings by category, severity, status |
| `github_audit_report` | Full markdown or JSON audit report |
| `github_run_all` | Execute all checks for an org/repo |

</details>

---

## Check Registry (45 checks)

<details>
<summary><b>Organization (ORG-001 to ORG-010)</b></summary>

| ID | Check | Severity |
|---|---|---|
| ORG-001 | 2FA not enforced | CRITICAL |
| ORG-002 | Default repo visibility is public | HIGH |
| ORG-003 | Members can create public repos | MEDIUM |
| ORG-004 | SSO/SAML not configured | HIGH |
| ORG-005 | Outside collaborators with access | MEDIUM |
| ORG-006 | Stale organization members | LOW |
| ORG-007 | Risky OAuth app authorizations | HIGH |
| ORG-008 | Over-permissive GitHub App installations | HIGH |
| ORG-009 | Insecure webhook URLs | MEDIUM |
| ORG-010 | Suspicious audit log activity | INFO |

</details>

<details>
<summary><b>Repository (REPO-001 to REPO-013)</b></summary>

| ID | Check | Severity |
|---|---|---|
| REPO-001 | Missing or weak branch protection | CRITICAL |
| REPO-002 | Secret scanning not enabled | HIGH |
| REPO-003 | Push protection not enabled | HIGH |
| REPO-004 | Code scanning not enabled | MEDIUM |
| REPO-005 | Open code scanning alerts | HIGH |
| REPO-006 | Dependabot not enabled | MEDIUM |
| REPO-007 | Critical Dependabot alerts | CRITICAL |
| REPO-008 | No SECURITY.md policy file | LOW |
| REPO-009 | Private vulnerability reporting off | LOW |
| REPO-010 | Unrestricted fork settings | LOW |
| REPO-011 | Insecure repo webhooks | MEDIUM |
| REPO-012 | Read-write deploy keys | HIGH |
| REPO-013 | Missing CODEOWNERS file | LOW |

</details>

<details>
<summary><b>Actions (ACT-001 to ACT-008)</b></summary>

| ID | Check | Severity |
|---|---|---|
| ACT-001 | Script injection via untrusted inputs | CRITICAL |
| ACT-002 | pull_request_target with checkout | CRITICAL |
| ACT-003 | Over-permissive GITHUB_TOKEN | HIGH |
| ACT-004 | Unpinned third-party actions | MEDIUM |
| ACT-005 | Self-hosted runner exposure | HIGH |
| ACT-006 | Missing environment protection rules | MEDIUM |
| ACT-007 | Secret exfiltration patterns | HIGH |
| ACT-008 | OIDC misconfiguration | MEDIUM |

</details>

<details>
<summary><b>Secrets (SEC-001 to SEC-005)</b></summary>

| ID | Check | Severity |
|---|---|---|
| SEC-001 | Secret scanning coverage gaps | HIGH |
| SEC-002 | Unresolved secret scanning alerts | CRITICAL |
| SEC-003 | Push protection bypasses | HIGH |
| SEC-004 | No custom secret patterns | LOW |
| SEC-005 | Overly broad secret scoping | MEDIUM |

</details>

<details>
<summary><b>Supply Chain (SUP-001 to SUP-005)</b></summary>

| ID | Check | Severity |
|---|---|---|
| SUP-001 | Dependency graph not enabled | MEDIUM |
| SUP-002 | Dependabot security updates off | HIGH |
| SUP-003 | No SBOM generation | LOW |
| SUP-004 | Critical known vulnerabilities | CRITICAL |
| SUP-005 | Stale unfixed vulnerabilities (>90 days) | HIGH |

</details>

<details>
<summary><b>Access Control (ACC-001 to ACC-004)</b></summary>

| ID | Check | Severity |
|---|---|---|
| ACC-001 | Over-permissive team access | HIGH |
| ACC-002 | External collaborators with write+ | MEDIUM |
| ACC-003 | Over-scoped GitHub Apps | HIGH |
| ACC-004 | Classic PATs with broad scopes | HIGH |

</details>

---

## Architecture

```
src/
├── index.ts                    Entry point + MCP stdio
├── types/
│   └── index.ts                CheckResult, ToolDef, ToolContext, ToolResult
├── github/
│   └── client.ts               GitHubClientFactory (lazy Octokit + GraphQL)
├── protocol/
│   ├── tools.ts                39 tool definitions (Zod schemas)
│   └── mcp-server.ts           MCP server + stdio transport
├── org/                        Organization checks (ORG-001..010)
│   ├── security.ts             2FA, visibility, member privileges
│   ├── sso.ts                  SSO/SAML via GraphQL
│   ├── members.ts              Outside collaborators, stale members
│   ├── apps.ts                 OAuth apps, GitHub App installations
│   ├── webhooks.ts             Insecure webhook URLs
│   └── audit-log.ts            Suspicious audit log patterns
├── repo/                       Repository checks (REPO-001..013)
│   ├── branch-protection.ts    Branch protection rules
│   ├── secret-scanning.ts      Secret scanning + push protection
│   ├── code-scanning.ts        CodeQL enabled, open alerts
│   ├── dependabot.ts           Dependabot enabled, critical alerts
│   ├── settings.ts             SECURITY.md, vuln reporting, forks
│   ├── webhooks.ts             Insecure repo webhooks
│   ├── deploy-keys.ts          Deploy key permissions
│   └── codeowners.ts           CODEOWNERS file
├── actions/                    GitHub Actions checks (ACT-001..008)
│   ├── injection.ts            Script injection via untrusted inputs
│   ├── pr-target.ts            pull_request_target + checkout
│   ├── permissions.ts          GITHUB_TOKEN default permissions
│   ├── pinning.ts              Unpinned third-party actions
│   ├── runners.ts              Self-hosted runner exposure
│   ├── environments.ts         Environment protection rules
│   ├── secrets.ts              Secret exfiltration patterns
│   └── oidc.ts                 OIDC configuration
├── secrets/                    Secret management checks (SEC-001..005)
│   ├── scanning.ts             Coverage + alert triage
│   ├── push-protection.ts      Push protection bypasses
│   ├── patterns.ts             Custom secret patterns
│   └── scoping.ts              Env/repo/org secret scoping
├── supply-chain/               Supply chain checks (SUP-001..005)
│   ├── dependency-graph.ts     Dependency graph enabled
│   ├── dependabot-updates.ts   Security updates config
│   ├── sbom.ts                 SBOM generation
│   └── vulnerabilities.ts      Known vulns, stale unfixed
├── access/                     Access control checks (ACC-001..004)
│   ├── teams.ts                Team permission audit
│   ├── collaborators.ts        External collaborators
│   ├── github-apps.ts          GitHub App permissions
│   └── tokens.ts               Classic vs fine-grained PATs
└── meta/                       Aggregation + reporting
    ├── list-checks.ts          CHECK_REGISTRY (45 checks)
    ├── summary.ts              Findings aggregation
    ├── report.ts               Markdown/JSON report
    └── run-all.ts              Execute all checks
```

**Design decisions:**

- **Single Octokit instance** &mdash; GitHub API is global (no regions). Lazy initialization on first API call.
- **Uniform CheckResult** &mdash; Every check returns the same structure: checkId, severity, status, details, remediation. Same pattern as [cloud-audit-mcp](https://github.com/badchars/cloud-audit-mcp).
- **Static workflow analysis** &mdash; Actions checks fetch YAML via Contents API and use regex analysis. GitHub has no parsed workflow API.
- **Enterprise graceful degradation** &mdash; Enterprise-only features (audit log, credential authorizations, SSO) return `NOT_APPLICABLE` instead of errors.
- **In-memory findings** &mdash; Session-scoped findings array. No database, no persistence. Run `github_audit_summary` or `github_audit_report` to aggregate.
- **4 dependencies** &mdash; `@modelcontextprotocol/sdk`, `@octokit/rest`, `@octokit/graphql`, `zod`. Nothing else.

---

## Authentication

| Token Type | Required Scopes |
|---|---|
| **Classic PAT** | `repo`, `admin:org`, `admin:org_hook`, `admin:repo_hook` |
| **Fine-grained PAT** (recommended) | Org: Members + Administration (read). Repo: Administration, Code scanning, Dependabot, Secret scanning, Actions, Environments, Webhooks (read) |
| **GitHub App** | Same repository/org permissions as fine-grained PAT |

The token is read from the `GITHUB_TOKEN` environment variable.

---

## Part of the MCP Security Suite

| Project | Domain | Tools |
|---|---|---|
| [hackbrowser-mcp](https://github.com/badchars/hackbrowser-mcp) | Browser-based security testing | 39 tools, Firefox, injection testing |
| [cloud-audit-mcp](https://github.com/badchars/cloud-audit-mcp) | Cloud security (AWS/Azure/GCP) | 38 tools, 60+ checks |
| **github-security-mcp** | GitHub security posture | 39 tools, 45 checks |

---

## Limitations

- Requires a GitHub PAT or GitHub App token with appropriate scopes
- Some checks require GitHub Enterprise Cloud (audit log, credential authorizations, SSO) &mdash; these gracefully return NOT_APPLICABLE on free/Team plans
- Actions workflow analysis is regex-based (no AST parsing) &mdash; may miss complex injection patterns
- Rate limiting: GitHub API allows 5,000 requests/hour for authenticated users. A full org audit with many repos may approach this limit
- macOS / Linux (Windows not tested)

---

<p align="center">
<b>For authorized security testing and assessment only.</b><br>
Always ensure you have proper authorization before auditing any organization.
</p>

<p align="center">
  <a href="LICENSE">MIT License</a> &bull; Built with Bun + TypeScript
</p>
