# Existing GitHub Security Tools - Knowledge Base

> Research compiled from academic papers, tool documentation, and web sources (2024-2026).
> Used for README positioning and implementation planning of github-security-mcp.

---

## 1. Tool Landscape Overview

The GitHub security tooling ecosystem is fragmented across multiple specialized tools, each covering a narrow slice of the attack surface. No single tool provides comprehensive GitHub security posture assessment. The landscape breaks down into:

- **Workflow SAST scanners** (zizmor, actionlint, poutine, semgrep) -- analyze `.github/workflows/*.yml` files
- **Org/repo config auditors** (Legitify, Allstar, GitGat) -- check GitHub API settings
- **Project health scorers** (OpenSSF Scorecard) -- score open-source project security hygiene
- **Runtime CI/CD monitors** (StepSecurity Harden-Runner) -- EDR-like agent on runners
- **Dependency scanners** (Dependabot, Socket.dev) -- CVE and supply chain risk
- **Secret detectors** (ggshield/GitGuardian) -- hardcoded credentials in code
- **Dependency pinners** (frizbee, pinny, scharf) -- single-purpose autofix tools
- **MCP wrappers** (GitHub MCP Server, GHAS MCP Server) -- raw API access, zero analysis

**Key insight:** No existing tool or MCP server performs proactive, holistic GitHub security auditing via MCP.

---

## 2. Scanner Coverage Matrix (Academic Paper)

Source: ["Unpacking Security Scanners for GitHub Actions Workflows" (arXiv:2601.14455, Jan 2026)](https://arxiv.org/html/2601.14455v1)

| Tool | Rules | AIW | CFW | EPW | GRCW | HGW | IW | KVCW | SEW | TMW | UDW | Auto-Fix |
|------|-------|-----|-----|-----|------|-----|----|----|-----|-----|-----|----------|
| **zizmor** | 23+ | Y | Y | Y | Y | Y | Y | - | Y | Y | Y | No |
| **actionlint** | 36 | Y | Y | Y | Y | Y | Y | Y | - | - | - | No |
| **poutine** | 13 | Y | Y | Y | Y | Y | Y | Y | Y | Y | - | No |
| **scorecard** | 5 | - | - | - | - | Y | Y | - | - | - | Y | No |
| **semgrep** | 3 | - | - | - | - | - | Y | - | - | Y | - | Yes |
| **ggshield** | 1 | - | - | - | - | - | - | - | Y | - | - | No |
| **frizbee** | 1 | - | - | - | - | - | - | - | - | - | Y | Yes |
| **pinny** | 1 | - | - | - | - | - | - | - | - | - | Y | Yes |
| **scharf** | 1 | - | - | - | - | - | - | - | - | - | Y | Yes |

**Two scanner families identified:**
1. General-purpose (zizmor, poutine, scorecard) -- multi-class coverage, different philosophies
2. Single-purpose (frizbee, pinny, scharf, ggshield) -- deep on one risk, often with autofix

**Recommended combination (from paper):** actionlint (syntax) + poutine (general security) + frizbee (dependency pinning) + zizmor or scorecard (policy coverage)

---

## 3. Weakness Taxonomy (10 Categories)

From the academic analysis (arXiv:2601.14455):

| Code | Weakness Category | CWE References | Description |
|------|-------------------|----------------|-------------|
| **AIW** | Artifact Integrity Weakness | CWE-353, CWE-494 | Unsigned or unverified build artifacts |
| **CFW** | Control Flow Weakness | CWE-571 | Unsound conditions, always-true checks |
| **EPW** | Excessive Permission Weakness | CWE-250, CWE-732 | Over-scoped workflow/token permissions |
| **GRCW** | GitHub Runner Compatibility Weakness | CWE-477, CWE-440 | Deprecated runners, label mismatches |
| **HGW** | Hardening Gap Weakness | CWE-223 | Missing security hardening configurations |
| **IW** | Injection Weakness | CWE-20, CWE-94 | Template injection via `${{ }}` expressions |
| **KVCW** | Known Vulnerable Component Weakness | CWE-1395 | Actions with disclosed CVEs |
| **SEW** | Secrets Exposure Weakness | CWE-200, CWE-522 | Credential leakage from workflows |
| **TMW** | Trigger Misuse Weakness | CWE-862 | Dangerous `pull_request_target`, `workflow_run` |
| **UDW** | Unpinned Dependency Weakness | CWE-829 | Actions/images not pinned to SHA |

---

## 4. Individual Tool Analysis

### 4.1 Zizmor

- **Repository:** [github.com/zizmorcore/zizmor](https://github.com/zizmorcore/zizmor)
- **Website:** [zizmor.sh](https://zizmor.sh/)
- **Language:** Rust
- **Focus:** GitHub Actions workflow static analysis
- **Rules:** 34 (covers all 10 weakness categories)

**Complete Rule List:**
anonymous-definition, archived-uses, artipacked, bot-conditions, cache-poisoning, concurrency-limits, dangerous-triggers, dependabot-cooldown, dependabot-execution, excessive-permissions, forbidden-uses, github-env, hardcoded-container-credentials, impostor-commit (requires API), insecure-commands, known-vulnerable-actions, misfeature, obfuscation, overprovisioned-secrets, ref-confusion, ref-version-mismatch, secrets-inherit, secrets-outside-env, self-hosted-runner, stale-action-refs, superfluous-actions, template-injection, undocumented-permissions, unpinned-images, unpinned-uses, unredacted-secrets, unsound-condition, unsound-contains, use-trusted-publishing

**Unique Strengths:**
- Broadest GitHub Actions coverage (34 rules, all 10 weakness categories)
- Offline-first (no GitHub API needed by default)
- SARIF output for GitHub Security tab integration
- Adjustable sensitivity (pedantic/auditor personas)
- Adopted by Grafana Labs and major OSS projects

**Cannot Do:** Org settings, repo settings, member permissions, secrets in source code, runtime monitoring, GitHub Apps/deploy keys/PATs audit

### 4.2 actionlint

- **Repository:** [github.com/rhysd/actionlint](https://github.com/rhysd/actionlint)
- **Website:** [rhysd.github.io/actionlint](https://rhysd.github.io/actionlint/)
- **Language:** Go
- **Focus:** GitHub Actions workflow correctness + limited security
- **Rules:** ~38 check categories

**Check Categories:**
YAML syntax, expression syntax/type checking, script integration (shellcheck + pyflakes), security (script injection, hardcoded credentials), workflow config (job deps, matrix, events, cron), runner validation, action validation (100+ popular action inputs), ID/naming, permissions, reusable workflows, deprecated features, YAML anchors/aliases

**Unique Strengths:**
- Excellent syntax and correctness checking (primary purpose)
- shellcheck/pyflakes integration for embedded scripts
- Fast (Go-based), mature, widely adopted

**Cannot Do:** Comprehensive security auditing (not its purpose), supply chain risks, org/repo settings, runtime monitoring, secret scanning

### 4.3 OpenSSF Scorecard

- **Repository:** [github.com/ossf/scorecard](https://github.com/ossf/scorecard)
- **Website:** [scorecard.dev](https://scorecard.dev/)
- **Language:** Go
- **Focus:** Open source project security health scoring (0-10 per check)
- **Checks:** 20

**Complete Check List:**
Binary-Artifacts, Branch-Protection, CI-Tests, CII-Best-Practices, Code-Review, Contributors, Dangerous-Workflow, Dependency-Update-Tool, Fuzzing, License, Maintained, Packaging, Pinned-Dependencies, SAST, SBOM, Security-Policy, Signed-Releases, Token-Permissions, Vulnerabilities, Webhooks

**Unique Strengths:**
- Industry standard backed by OpenSSF/Google
- REST API for batch scoring of public repos
- Structured Results (v5) allows granular heuristic selection
- Integrated into other tools (Legitify uses Scorecard internally)

**Cannot Do:** Org-level misconfiguration audit, secrets scanning, runtime CI/CD monitoring, GitHub Apps/deploy keys/PATs audit

### 4.4 Poutine (BoostSecurity)

- **Repository:** [github.com/boostsecurityio/poutine](https://github.com/boostsecurityio/poutine)
- **Language:** Go
- **Focus:** Build pipeline security scanner (GitHub Actions + GitLab CI/CD)
- **Rules:** 13 covering 7 weakness categories

**Key Features:**
- Build-time dependency inventory (Actions, GitLab imports, Docker containers, CircleCI orbs)
- Track known CVEs in build dependencies
- Custom Rego rules for extending checks
- Stale branch analysis for `pull_request_target` exploits
- Living Off The Pipeline (LOTP) tool detection

**MCP Integration (2025):**
- New Poutine MCP Server introduced
- Local analysis capabilities via MCP
- Enables interoperability with AI agent workflows

**Cannot Do:** Org-level settings, member permissions, deploy keys, PATs, runtime monitoring

### 4.5 Legitify

- **Repository:** [github.com/Legit-Labs/legitify](https://github.com/Legit-Labs/legitify)
- **Website:** [legitsecurity.com/legitify](https://www.legitsecurity.com/legitify)
- **Language:** Go
- **Focus:** Org/repo misconfiguration scanning (GitHub + GitLab)
- **Policies:** ~54 GitHub + ~50 GitLab

**Policy Namespaces:**

| Namespace | Count | Examples |
|-----------|-------|----------|
| **Enterprise** | 12 | Advanced Security auto-enable, SSO enforcement, 2FA, prevent public repos, prevent forking |
| **Organization** | 7 | Default member permissions, SSO, 2FA, webhook SSL/secret, secret rotation |
| **Repository** | 26 | Branch protection (12+ checks), secret scanning, OSSF score threshold, vulnerability alerts, forking controls, webhook security |
| **Actions** | 4 | Token permissions, verified actions only, repo restrictions, PR approval prevention |
| **Members** | 3 | Admin activity, member activity, owner count limit |
| **Runner Groups** | 2 | Private repo restriction, selected repo restriction |

**Unique Strengths:**
- Broadest org/repo misconfiguration coverage of any OSS tool
- Enterprise-level policy checks (SSO, 2FA, Advanced Security)
- Integrates OpenSSF Scorecard internally
- Remediation steps documented for every policy

**Cannot Do:** Workflow file static analysis, secrets-in-code detection, runtime monitoring, GitHub App permissions audit, deploy key inventory, PAT tracking

### 4.6 Allstar

- **Repository:** [github.com/ossf/allstar](https://github.com/ossf/allstar)
- **Type:** GitHub App (continuous enforcement)
- **Policies:** 9

**Policy List:**
Branch Protection, Binary Artifacts, CODEOWNERS, Outside Collaborators, SECURITY.md, Dangerous Workflow, Generic Scorecard Check, GitHub Actions, Repository Administrators

**Unique Strengths:**
- Continuous enforcement (not just scanning)
- Auto-fix capability for some policies
- Org-wide deployment with opt-out model

**Cannot Do:** Deep workflow analysis, secrets detection, audit logging, member/contributor permissions, GitHub Apps/deploy keys/webhooks

### 4.7 StepSecurity

- **Repository:** [github.com/step-security](https://github.com/step-security)
- **Products:** Harden-Runner, Secure Workflows, Maintained Actions
- **Type:** SaaS + GitHub Action

| Product | What It Does |
|---------|-------------|
| **Harden-Runner** | Network egress monitoring with domain allowlist; file integrity monitoring; process activity monitoring; anomaly detection via baseline; prevents secret exfiltration and source code tampering |
| **Secure Workflows** | Auto-pins actions to commit SHAs; enforces least-privilege GITHUB_TOKEN permissions; creates hardening PRs |
| **Maintained Actions** | Drop-in replacements for third-party actions (hardened, verified, maintained) |
| **Action Security Scores** | Tracks every action across repos; assigns risk scores |

**Unique Strengths:**
- Only tool with runtime CI/CD monitoring (EDR-like)
- Caught the tj-actions/changed-files supply chain attack in real-time
- Auto-remediation via PR creation
- Used by 5,000+ open source projects

**Cannot Do:** Org-level settings, repo configurations, secrets in source code, GitHub Apps/deploy keys/PATs, works only in GitHub Actions context

### 4.8 GitGat

- **Repository:** [github.com/scribe-public/gitgat](https://github.com/scribe-public/gitgat)
- **Type:** Policy-as-Code (OPA/Rego)
- **Checks:** 5-6 areas

**Covers:** 2FA enforcement, repository visibility, deploy key validation, SSH key control, branch protection mapping

**Unique Strengths:** OPA/Rego extensible, tracks posture changes over time

**Cannot Do:** Workflow analysis, secrets detection, runtime monitoring, enterprise auditing, comprehensive coverage (very limited check count, low maintenance)

### 4.9 GitGuardian (ggshield)

- **Repository:** [github.com/GitGuardian/ggshield](https://github.com/GitGuardian/ggshield)
- **Focus:** Secret detection in code
- **Detection:** 500+ secret types with validation (checks if credentials are active)
- **Integration:** Pre-commit hooks, GitHub Action, CI integration
- **Free for:** Public repos

### 4.10 frizbee, pinny, scharf

Single-purpose dependency pinning tools:

| Tool | What It Does | Auto-Fix |
|------|-------------|----------|
| **frizbee** | Pins actions to commit SHAs | Yes |
| **pinny** | Pins actions to commit SHAs | Yes |
| **scharf** | Pins actions to commit SHAs | Yes |

---

## 5. GitHub Built-in Security Features

### 5.1 GitHub Advanced Security (GHAS)

As of March 2025, GHAS split into two standalone products:
- **GitHub Secret Protection** ($19/committer/mo)
- **GitHub Code Security** (separate pricing)

| Feature | What It Does |
|---------|-------------|
| **CodeQL** | Semantic code analysis, 2000+ queries across 10+ languages |
| **Secret Scanning** | 200+ secret patterns, push protection |
| **Dependabot** | Dependency vulnerability alerts + auto-update PRs |
| **Security Advisories** | GHSA database (62 advisories published in 2025) |
| **Code Scanning** | SARIF-based, runs in Actions |
| **Dependency Review** | PR-time dependency change analysis |

### 5.2 Dependabot Limitations

- Only scans default branch
- Does not scan archived repositories
- Only manifest/lock file dependencies (misses some transitive deps)
- Cannot detect malicious packages (typosquatting, protestware)
- Cannot analyze package behavior
- No org/repo settings auditing
- No workflow security analysis

### 5.3 Socket.dev

- **Type:** SaaS with GitHub App
- **Focus:** Supply chain risk detection
- **Detection:** 70+ signals across 5 categories

| Category | Examples |
|----------|---------|
| Supply Chain Risk | Typosquatting, install scripts, protestware, troll packages |
| Code Behavior | Network access, filesystem access, shell access, obfuscation |
| Package Metadata | Invalid manifests, mutable dependencies |
| Maintainer Behavior | New maintainer on popular package, ownership transfers |
| Known Vulnerabilities | CVE-based detection |

**Cannot Do:** GitHub Actions workflow analysis, org/repo configuration auditing

---

## 6. Existing MCP Servers for GitHub Security

### 6.1 GitHub Official MCP Server

- **Repository:** [github.com/github/github-mcp-server](https://github.com/github/github-mcp-server)
- **Status:** Generally available (remote server since Sep 2025)

**Security-related toolsets:**
- `code_security` -- get/list code scanning alerts
- `dependabot` -- get/list Dependabot alerts
- `secret_protection` -- get/list secret scanning alerts
- `security_advisories` -- advisory data

**Critical point:** This is NOT a security auditing tool. It surfaces existing GitHub security features to AI agents but performs zero security analysis. It is raw API access only.

### 6.2 GHAS MCP Server (rajbos)

- **Repository:** [github.com/rajbos/ghas-mcp-server](https://github.com/rajbos/ghas-mcp-server)
- **Tools:** 3 only
  - `list_dependabot_alerts`
  - `list_secret_scanning_alerts`
  - `list_code_scanning_alerts`

**Critical point:** Thin MCP wrapper around existing GHAS alerts. No analysis, no org audit, no posture assessment.

### 6.3 Poutine MCP Server (BoostSecurity)

- Introduced in 2025
- Local analysis of build pipelines via MCP
- Focused exclusively on workflow file SAST (13 rules)
- Does NOT audit org settings, repo configs, members, or access controls

---

## 7. Key Gaps That No Existing Tool Covers

### Gap 1: GitHub App Installation Audit
No tool audits permissions granted to installed GitHub Apps, whether they have excessive scopes, or whether unused apps remain installed.

### Gap 2: Deploy Key Inventory and Audit
Only GitGat partially covers deploy keys. No comprehensive deploy key auditing (which repos, read vs write, last used, rotation age).

### Gap 3: PAT/Token Inventory and Scope Analysis
No open-source tool audits fine-grained PAT usage, identifies over-scoped tokens, or tracks token age/rotation compliance across an organization.

### Gap 4: Webhook Security Audit (Deep)
Legitify checks SSL and secret presence, but no tool audits webhook destinations, validates endpoints, or identifies webhooks pointing to suspicious/external URLs.

### Gap 5: Cross-Repository Secret Exposure Analysis
No tool maps which secrets are shared across repositories and identifies blast radius if one repo is compromised.

### Gap 6: GitHub Actions Marketplace Action Risk Assessment
Zizmor checks for known CVEs, but no tool does deep trust assessment of third-party actions (maintainer reputation, code review, update frequency, dependency chain analysis).

### Gap 7: AI-Driven Prioritization and Fix Generation
All existing tools generate reports. No tool provides AI-driven prioritization of findings, contextual risk scoring, or generates ready-to-apply fixes with full context awareness.

### Gap 8: Composite/Holistic Security Posture
No single tool combines org-level + repo-level + workflow-level + runtime auditing. Users must cobble together 3-5 tools.

### Gap 9: GitHub Environment and Secret Scoping Audit
No tool comprehensively audits GitHub Environments (protection rules, deployment branches, required reviewers) and whether secrets are properly scoped to environments vs globally available.

### Gap 10: Historical Security Posture Tracking
Only GitGat attempts posture-over-time tracking. No tool provides trend analysis, regression detection, or compliance drift alerting.

### Gap 11: Custom Security Policy Engine
Legitify has fixed policies. No MCP tool lets an AI agent dynamically create and evaluate custom security policies based on compliance requirements (SOC2, ISO 27001, NIST).

---

## 8. Competitive Differentiation for github-security-mcp

### What makes it different

**Every existing tool is either:**
1. A workflow SAST scanner (zizmor, poutine, actionlint) -- only looks at `.yml` files
2. A config auditor (Legitify, Allstar) -- CLI report, no AI integration
3. A raw API wrapper (GitHub MCP Server, GHAS MCP) -- zero security analysis
4. A runtime monitor (StepSecurity) -- requires per-workflow setup
5. A dependency scanner (Dependabot, Socket) -- package-level only

**github-security-mcp is the first tool that:**
- Provides **full org/repo/actions/secrets/supply-chain/access posture assessment** via MCP
- Gives AI agents the ability to **call GitHub APIs directly** and **apply security heuristics** against the returned data
- Performs **holistic cross-domain analysis** that no single existing tool can do
- Supports **natural language queries** like "What are my riskiest repos?" or "Which PATs haven't been rotated in 90 days?"
- Enables **AI-driven prioritization** of findings by actual risk, not just severity labels
- Generates **contextual fix commands** or API calls with full context awareness

### Coverage comparison

| Domain | github-security-mcp | Existing Tools |
|--------|---------------------|----------------|
| Org settings (SSO, 2FA, permissions) | MCP tools | Legitify (CLI only) |
| Repo settings (branch protection, visibility) | MCP tools | Legitify, Scorecard (partial) |
| Workflow file security | MCP tools + embedded analysis | Zizmor, poutine, actionlint |
| GitHub App permissions audit | MCP tools | **Nobody** |
| Deploy key inventory | MCP tools | GitGat (partial, low maintenance) |
| PAT/token scope analysis | MCP tools | **Nobody** |
| Webhook security (deep) | MCP tools | Legitify (SSL/secret check only) |
| Secret blast radius mapping | MCP tools | **Nobody** |
| Environment protection rules | MCP tools | **Nobody** |
| AI-driven prioritization | Built-in (MCP + LLM) | **Nobody** |
| Holistic posture score | Built-in | **Nobody** (3-5 tool combo needed) |

### Positioning statement

> Prowler / ScoutSuite for cloud, Zizmor / Legitify for GitHub -- but all CLI/dashboard.
> github-security-mcp is the first tool that gives AI agents full GitHub security posture
> assessment via MCP: org, repo, actions, secrets, supply chain, access controls -- not
> just workflow SAST, but the complete picture.

---

## 9. Sources

- [OpenSSF Scorecard](https://github.com/ossf/scorecard) | [Checks docs](https://github.com/ossf/scorecard/blob/main/docs/checks.md)
- [Allstar](https://github.com/ossf/allstar)
- [Zizmor](https://github.com/zizmorcore/zizmor) | [Audit docs](https://docs.zizmor.sh/audits/)
- [actionlint](https://github.com/rhysd/actionlint) | [Checks docs](https://github.com/rhysd/actionlint/blob/main/docs/checks.md)
- [StepSecurity Harden-Runner](https://github.com/step-security/harden-runner) | [stepsecurity.io](https://www.stepsecurity.io/)
- [Legitify](https://github.com/Legit-Labs/legitify) | [Policies](https://policies.legitify.dev/)
- [GitGat](https://github.com/scribe-public/gitgat)
- [Socket.dev](https://socket.dev/)
- [Poutine](https://github.com/boostsecurityio/poutine)
- [GitGuardian ggshield](https://github.com/GitGuardian/ggshield)
- [GitHub MCP Server](https://github.com/github/github-mcp-server)
- [GHAS MCP Server](https://github.com/rajbos/ghas-mcp-server)
- [GitHub Security Lab](https://securitylab.github.com/)
- [Unpacking Security Scanners for GitHub Actions Workflows (arXiv:2601.14455, Jan 2026)](https://arxiv.org/html/2601.14455v1)
- [Grafana Labs: Detecting Vulnerable GitHub Actions at Scale with Zizmor](https://grafana.com/blog/how-to-detect-vulnerable-github-actions-at-scale-with-zizmor/)
- [Awesome GitHub Actions Security](https://github.com/johnbillion/awesome-github-actions-security)
- [OpenSSF: Mitigating Attack Vectors in GitHub Workflows](https://openssf.org/blog/2024/08/12/mitigating-attack-vectors-in-github-workflows/)
- [Wiz: Hardening GitHub Actions](https://www.wiz.io/blog/github-actions-security-guide)
- [GitHub Blog: Practical Guide to GitHub MCP Server](https://github.blog/ai-and-ml/generative-ai/a-practical-guide-on-how-to-use-the-github-mcp-server/)
