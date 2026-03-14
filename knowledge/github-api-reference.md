# GitHub Security API Reference

Comprehensive catalog of GitHub REST and GraphQL API endpoints for security auditing.
Used as the knowledge base for implementing github-security-mcp tools.

---

## Table of Contents

1. [Organization Security](#1-organization-security)
2. [Repository Security](#2-repository-security)
3. [GitHub Advanced Security (GHAS)](#3-github-advanced-security-ghas)
4. [Access Control](#4-access-control)
5. [GitHub Actions](#5-github-actions)
6. [Rate Limit Considerations](#6-rate-limit-considerations)
7. [Authentication Comparison](#7-authentication-comparison)
8. [Enterprise vs Free/Team API Availability](#8-enterprise-vs-freeteam-api-availability)
9. [Octokit SDK Method Mapping](#9-octokit-sdk-method-mapping)
10. [Beta/Preview APIs and Undocumented Endpoints](#10-betapreview-apis-and-undocumented-endpoints)

---

## 1. Organization Security

### 1.1 Organization Settings (2FA, Member Privileges, Visibility)

**REST:**

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/orgs/{org}` | Returns org settings including `two_factor_requirement_enabled`, `default_repository_permission`, `members_can_create_repositories`, `members_can_create_public_repositories`, `members_can_create_private_repositories`, `members_can_create_internal_repositories`, `members_can_fork_private_repositories`, `members_can_create_pages`, `web_commit_signoff_required` |
| `PATCH` | `/orgs/{org}` | Update org settings (same fields) |

**Key response fields for audit:**

- `two_factor_requirement_enabled` -- whether 2FA is enforced
- `default_repository_permission` -- `read`, `write`, `admin`, or `none`
- `members_can_create_repositories` -- boolean
- `members_can_create_public_repositories` -- boolean
- `members_can_create_private_repositories` -- boolean
- `members_can_create_internal_repositories` -- boolean (Enterprise Cloud only)
- `members_can_fork_private_repositories` -- boolean
- `web_commit_signoff_required` -- boolean

**Permissions:** Authenticated user. `admin:org` scope for sensitive fields. Fine-grained PAT: "Administration" org permission (read).

**GraphQL:**

```graphql
query {
  organization(login: "ORG") {
    requiresTwoFactorAuthentication
    membersCanForkPrivateRepositories
    defaultRepositoryPermissionSetting  # NONE, READ, WRITE, ADMIN
    membersCanCreateRepositoriesSetting # ALL, PRIVATE, DISABLED
    ipAllowListEnabledSetting           # ENABLED, DISABLED (Enterprise Cloud)
    samlIdentityProvider { ssoUrl, issuer }
  }
}
```

### 1.2 SSO/SAML Enforcement

**REST:**

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/orgs/{org}/credential-authorizations` | List SAML SSO authorizations for an org |
| `DELETE` | `/orgs/{org}/credential-authorizations/{credential_id}` | Remove a SAML SSO authorization |

**Permissions:** `admin:org` scope. Owner only. **Enterprise Cloud only.**

**GraphQL:**

```graphql
query {
  organization(login: "ORG") {
    samlIdentityProvider {
      ssoUrl
      issuer
      externalIdentities(first: 100) {
        nodes {
          samlIdentity { nameId }
          user { login }
        }
      }
    }
  }
}
```

### 1.3 Member Management

**REST:**

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/orgs/{org}/members` | List all org members |
| `GET` | `/orgs/{org}/members?filter=2fa_disabled` | List members without 2FA |
| `GET` | `/orgs/{org}/members/{username}` | Check membership |
| `GET` | `/orgs/{org}/memberships/{username}` | Get membership details (role: admin/member) |
| `GET` | `/orgs/{org}/outside_collaborators` | List outside collaborators |
| `DELETE` | `/orgs/{org}/outside_collaborators/{username}` | Remove outside collaborator |
| `PUT` | `/orgs/{org}/outside_collaborators/{username}` | Convert member to outside collaborator |
| `GET` | `/orgs/{org}/pending_invitations` | List pending invitations |
| `GET` | `/orgs/{org}/failed_invitations` | List failed invitations |

**Permissions:** `admin:org` or `read:org` scope. Fine-grained PAT: "Members" org permission (read).

### 1.4 Audit Log

**REST:**

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/orgs/{org}/audit-log` | Get org audit log events |
| `GET` | `/enterprises/{enterprise}/audit-log` | Get enterprise audit log |

Query parameters: `phrase` (search), `include` (web/git/all), `after` (cursor), `before`, `order` (asc/desc), `per_page`.

**Permissions:** `admin:org` scope. Owner only. Audit log REST API available on **Enterprise Cloud** and **Enterprise Server 3.7+**. Data retained 90-180 days.

**GraphQL (Enterprise Cloud only):**

```graphql
query {
  organization(login: "ORG") {
    auditLog(first: 100, query: "action:repo.create") {
      edges {
        node {
          ... on RepositoryAuditEntryData {
            repository { name }
          }
          ... on AuditEntry {
            action
            actorLogin
            createdAt
          }
        }
      }
    }
  }
}
```

### 1.5 Webhooks (Organization-Level)

**REST:**

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/orgs/{org}/hooks` | List org webhooks |
| `POST` | `/orgs/{org}/hooks` | Create org webhook |
| `GET` | `/orgs/{org}/hooks/{hook_id}` | Get an org webhook |
| `PATCH` | `/orgs/{org}/hooks/{hook_id}` | Update org webhook |
| `DELETE` | `/orgs/{org}/hooks/{hook_id}` | Delete org webhook |
| `GET` | `/orgs/{org}/hooks/{hook_id}/config` | Get config |
| `GET` | `/orgs/{org}/hooks/{hook_id}/deliveries` | List deliveries |

**Security audit note:** Check for `insecure_ssl: "1"` (allows insecure connections) and verify webhook URLs are HTTPS.

**Permissions:** Org admin. Fine-grained PAT: "Webhooks" org permission (read/write).

### 1.6 GitHub App & OAuth App Installations

**REST:**

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/orgs/{org}/installations` | List GitHub App installations for org |
| `GET` | `/app/installations` | List installations for authenticated app |
| `GET` | `/app/installations/{installation_id}` | Get a single installation |
| `GET` | `/user/installations` | List app installations accessible to user |
| `DELETE` | `/app/installations/{installation_id}` | Uninstall an app |

**Permissions:** Org owner for `/orgs/{org}/installations`. `admin:org` scope.

### 1.7 Organization Secrets

**REST (Actions secrets):**

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/orgs/{org}/actions/secrets` | List org Actions secrets |
| `GET` | `/orgs/{org}/actions/secrets/{secret_name}` | Get an org secret (metadata only, not value) |
| `PUT` | `/orgs/{org}/actions/secrets/{secret_name}` | Create/update org secret |
| `DELETE` | `/orgs/{org}/actions/secrets/{secret_name}` | Delete org secret |
| `GET` | `/orgs/{org}/actions/secrets/{secret_name}/repositories` | List repos with access to secret |
| `GET` | `/orgs/{org}/actions/secrets/public-key` | Get org public key for encryption |

**REST (Dependabot secrets):**

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/orgs/{org}/dependabot/secrets` | List org Dependabot secrets |
| `GET` | `/orgs/{org}/dependabot/secrets/{secret_name}` | Get a Dependabot secret |
| `PUT` | `/orgs/{org}/dependabot/secrets/{secret_name}` | Create/update |
| `DELETE` | `/orgs/{org}/dependabot/secrets/{secret_name}` | Delete |
| `GET` | `/orgs/{org}/dependabot/secrets/{secret_name}/repositories` | List repos with access |

**REST (Codespaces secrets):**

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/orgs/{org}/codespaces/secrets` | List org Codespaces secrets |

**Permissions:** `admin:org` scope. Fine-grained PAT: "Secrets" org permission (read/write).

### 1.8 IP Allow List (Enterprise Cloud Only)

**REST:** No dedicated REST endpoints. Managed via GraphQL.

**GraphQL:**

```graphql
query {
  organization(login: "ORG") {
    ipAllowListEnabledSetting
    ipAllowListForInstalledAppsEnabledSetting
    ipAllowListEntries(first: 100) {
      nodes {
        allowListValue    # CIDR or IP
        name
        isActive
        createdAt
      }
    }
  }
}

# Mutations:
mutation {
  createIpAllowListEntry(input: {
    ownerId: "ORG_ID"
    allowListValue: "192.168.1.0/24"
    name: "Office"
    isActive: true
  }) { ipAllowListEntry { id } }
}

mutation {
  deleteIpAllowListEntry(input: { ipAllowListEntryId: "ID" }) {
    ipAllowListEntry { id }
  }
}

mutation {
  updateIpAllowListEnabledSetting(input: {
    ownerId: "ORG_ID"
    settingValue: ENABLED
  }) { organization { ipAllowListEnabledSetting } }
}
```

**Permissions:** Organization owner. Enterprise Cloud only.

### 1.9 Custom Repository Roles (Enterprise Cloud)

**REST:**

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/orgs/{org}/organization-roles` | List all custom org roles |
| `GET` | `/orgs/{org}/organization-roles/{role_id}` | Get a specific role |
| `POST` | `/orgs/{org}/organization-roles` | Create custom role |
| `PATCH` | `/orgs/{org}/organization-roles/{role_id}` | Update custom role |
| `DELETE` | `/orgs/{org}/organization-roles/{role_id}` | Delete custom role |
| `GET` | `/orgs/{org}/organization-roles/{role_id}/users` | List users assigned to role |
| `GET` | `/orgs/{org}/organization-roles/{role_id}/teams` | List teams assigned to role |

**Permissions:** Org owner. `admin:org` scope. **Enterprise Cloud only** (custom roles beyond the 5 built-in).

### 1.10 Security Managers

**REST (being deprecated Jan 2026, use Organization Roles instead):**

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/orgs/{org}/security-managers` | List security manager teams |
| `PUT` | `/orgs/{org}/security-managers/teams/{team_slug}` | Add team as security manager |
| `DELETE` | `/orgs/{org}/security-managers/teams/{team_slug}` | Remove team |

**Permissions:** Org owner. `admin:org` scope.

---

## 2. Repository Security

### 2.1 Branch Protection Rules

**REST:**

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/repos/{owner}/{repo}/branches/{branch}/protection` | Get full branch protection |
| `PUT` | `/repos/{owner}/{repo}/branches/{branch}/protection` | Update branch protection |
| `DELETE` | `/repos/{owner}/{repo}/branches/{branch}/protection` | Delete branch protection |
| `GET` | `/repos/{owner}/{repo}/branches/{branch}/protection/required_status_checks` | Get status check protection |
| `PATCH` | `/repos/{owner}/{repo}/branches/{branch}/protection/required_status_checks` | Update status checks |
| `DELETE` | `/repos/{owner}/{repo}/branches/{branch}/protection/required_status_checks` | Remove status checks |
| `GET` | `/repos/{owner}/{repo}/branches/{branch}/protection/required_status_checks/contexts` | Get status check contexts |
| `PUT` | `/repos/{owner}/{repo}/branches/{branch}/protection/required_status_checks/contexts` | Set contexts |
| `POST` | `/repos/{owner}/{repo}/branches/{branch}/protection/required_status_checks/contexts` | Add contexts |
| `DELETE` | `/repos/{owner}/{repo}/branches/{branch}/protection/required_status_checks/contexts` | Remove contexts |
| `GET` | `/repos/{owner}/{repo}/branches/{branch}/protection/required_pull_request_reviews` | Get PR review protection |
| `PATCH` | `/repos/{owner}/{repo}/branches/{branch}/protection/required_pull_request_reviews` | Update PR review protection |
| `DELETE` | `/repos/{owner}/{repo}/branches/{branch}/protection/required_pull_request_reviews` | Delete PR review enforcement |
| `GET` | `/repos/{owner}/{repo}/branches/{branch}/protection/enforce_admins` | Get admin enforcement |
| `POST` | `/repos/{owner}/{repo}/branches/{branch}/protection/enforce_admins` | Set admin enforcement |
| `DELETE` | `/repos/{owner}/{repo}/branches/{branch}/protection/enforce_admins` | Remove admin enforcement |
| `GET` | `/repos/{owner}/{repo}/branches/{branch}/protection/restrictions` | Get access restrictions |
| `DELETE` | `/repos/{owner}/{repo}/branches/{branch}/protection/restrictions` | Delete access restrictions |
| `GET` | `/repos/{owner}/{repo}/branches/{branch}/protection/restrictions/users` | Get users with push access |
| `PUT` | `/repos/{owner}/{repo}/branches/{branch}/protection/restrictions/users` | Set users |
| `POST` | `/repos/{owner}/{repo}/branches/{branch}/protection/restrictions/users` | Add users |
| `DELETE` | `/repos/{owner}/{repo}/branches/{branch}/protection/restrictions/users` | Remove users |
| `GET` | `/repos/{owner}/{repo}/branches/{branch}/protection/restrictions/teams` | Get teams with push access |
| `PUT` | `/repos/{owner}/{repo}/branches/{branch}/protection/restrictions/teams` | Set teams |
| `POST` | `/repos/{owner}/{repo}/branches/{branch}/protection/restrictions/teams` | Add teams |
| `DELETE` | `/repos/{owner}/{repo}/branches/{branch}/protection/restrictions/teams` | Remove teams |
| `GET` | `/repos/{owner}/{repo}/branches/{branch}/protection/restrictions/apps` | Get apps with push access |
| `PUT` | `/repos/{owner}/{repo}/branches/{branch}/protection/restrictions/apps` | Set apps |
| `POST` | `/repos/{owner}/{repo}/branches/{branch}/protection/restrictions/apps` | Add apps |
| `DELETE` | `/repos/{owner}/{repo}/branches/{branch}/protection/restrictions/apps` | Remove apps |
| `GET` | `/repos/{owner}/{repo}/branches/{branch}/protection/required_signatures` | Get commit signature protection |
| `POST` | `/repos/{owner}/{repo}/branches/{branch}/protection/required_signatures` | Create commit signature protection |
| `DELETE` | `/repos/{owner}/{repo}/branches/{branch}/protection/required_signatures` | Delete commit signature protection |

**Permissions:** Admin or owner on repo. Fine-grained PAT: "Administration" repo permission (read for GET, write for mutations).

**GraphQL:**

```graphql
query {
  repository(owner: "OWNER", name: "REPO") {
    branchProtectionRules(first: 100) {
      nodes {
        pattern
        isAdminEnforced
        allowsDeletions
        allowsForcePushes
        blocksCreations
        dismissesStaleReviews
        requiresApprovingReviews
        requiredApprovingReviewCount
        requiresCodeOwnerReviews
        requiresCommitSignatures
        requiresConversationResolution
        requiresLinearHistory
        requiresStatusChecks
        requiresStrictStatusChecks
        requiredStatusCheckContexts
        restrictsPushes
        restrictsReviewDismissals
        requireLastPushApproval
        lockBranch
        lockAllowsFetchAndMerge
        bypassPullRequestAllowances(first: 10) {
          nodes { actor { ... on User { login } ... on Team { slug } ... on App { slug } } }
        }
        bypassForcePushAllowances(first: 10) {
          nodes { actor { ... on User { login } ... on Team { slug } } }
        }
        pushAllowances(first: 10) {
          nodes { actor { ... on User { login } ... on Team { slug } } }
        }
        reviewDismissalAllowances(first: 10) {
          nodes { actor { ... on User { login } ... on Team { slug } } }
        }
      }
    }
  }
}
```

### 2.2 Repository Rulesets (New API, replaces branch protection + tag protection)

**REST:**

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/repos/{owner}/{repo}/rulesets` | List repo rulesets |
| `POST` | `/repos/{owner}/{repo}/rulesets` | Create a ruleset |
| `GET` | `/repos/{owner}/{repo}/rulesets/{ruleset_id}` | Get a ruleset |
| `PUT` | `/repos/{owner}/{repo}/rulesets/{ruleset_id}` | Update a ruleset |
| `DELETE` | `/repos/{owner}/{repo}/rulesets/{ruleset_id}` | Delete a ruleset |
| `GET` | `/repos/{owner}/{repo}/rules/branches/{branch}` | Get rules for a branch |
| `GET` | `/orgs/{org}/rulesets` | List org-level rulesets |
| `POST` | `/orgs/{org}/rulesets` | Create org-level ruleset |
| `GET` | `/orgs/{org}/rulesets/{ruleset_id}` | Get an org ruleset |
| `PUT` | `/orgs/{org}/rulesets/{ruleset_id}` | Update org ruleset |
| `DELETE` | `/orgs/{org}/rulesets/{ruleset_id}` | Delete org ruleset |
| `GET` | `/orgs/{org}/rulesets/rule-suites` | List org rule suite evaluations |
| `GET` | `/orgs/{org}/rulesets/rule-suites/{rule_suite_id}` | Get a rule suite |
| `GET` | `/repos/{owner}/{repo}/rulesets/rule-suites` | List repo rule suite evaluations |
| `GET` | `/repos/{owner}/{repo}/rulesets/rule-suites/{rule_suite_id}` | Get a repo rule suite |

**Rule types available:** `creation`, `update`, `deletion`, `required_linear_history`, `merge_queue`, `required_deployments`, `required_signatures`, `pull_request` (with `required_approving_review_count`, `dismiss_stale_reviews_on_push`, `require_code_owner_review`, `require_last_push_approval`, `required_review_thread_resolution`), `required_status_checks`, `non_fast_forward`, `commit_message_pattern`, `commit_author_email_pattern`, `committer_email_pattern`, `branch_name_pattern`, `tag_name_pattern`, `workflows`, `code_scanning`.

**Permissions:** Admin/owner on repo. Fine-grained PAT: "Administration" repo permission (read/write).

### 2.3 CODEOWNERS Detection

**REST:**

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/repos/{owner}/{repo}/codeowners/errors` | List CODEOWNERS errors |
| `GET` | `/repos/{owner}/{repo}/contents/CODEOWNERS` | Get CODEOWNERS from root |
| `GET` | `/repos/{owner}/{repo}/contents/.github/CODEOWNERS` | Get CODEOWNERS from .github |
| `GET` | `/repos/{owner}/{repo}/contents/docs/CODEOWNERS` | Get CODEOWNERS from docs |
| `GET` | `/repos/{owner}/{repo}/community/profile` | Community profile (includes `code_of_conduct`, `contributing`, `issue_template`, `pull_request_template`, `license`, `readme`) |

**Permissions:** Repo read access. CODEOWNERS errors endpoint requires repo admin.

### 2.4 Security Policy (SECURITY.md)

**REST:**

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/repos/{owner}/{repo}/contents/SECURITY.md` | Get security policy from root |
| `GET` | `/repos/{owner}/{repo}/contents/.github/SECURITY.md` | From .github dir |
| `GET` | `/repos/{owner}/{repo}/community/profile` | `security` field indicates presence |

**GraphQL:**

```graphql
query {
  repository(owner: "OWNER", name: "REPO") {
    securityPolicyUrl
    isSecurityPolicyEnabled
  }
}
```

### 2.5 Private Vulnerability Reporting

**REST:**

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/repos/{owner}/{repo}` | Response includes `private_vulnerability_reporting_enabled` field |
| `GET` | `/repos/{owner}/{repo}/private-vulnerability-reporting` | Check if PVR is enabled |
| `PUT` | `/repos/{owner}/{repo}/private-vulnerability-reporting` | Enable PVR |
| `DELETE` | `/repos/{owner}/{repo}/private-vulnerability-reporting` | Disable PVR |

**Permissions:** Repo admin. `security_events` scope or Fine-grained PAT: "Administration" repo permission (write).

### 2.6 Webhooks (Repository-Level)

**REST:**

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/repos/{owner}/{repo}/hooks` | List repository webhooks |
| `POST` | `/repos/{owner}/{repo}/hooks` | Create a webhook |
| `GET` | `/repos/{owner}/{repo}/hooks/{hook_id}` | Get a webhook |
| `PATCH` | `/repos/{owner}/{repo}/hooks/{hook_id}` | Update a webhook |
| `DELETE` | `/repos/{owner}/{repo}/hooks/{hook_id}` | Delete a webhook |
| `GET` | `/repos/{owner}/{repo}/hooks/{hook_id}/config` | Get webhook config (url, content_type, secret, insecure_ssl) |
| `PATCH` | `/repos/{owner}/{repo}/hooks/{hook_id}/config` | Update webhook config |
| `GET` | `/repos/{owner}/{repo}/hooks/{hook_id}/deliveries` | List deliveries |
| `POST` | `/repos/{owner}/{repo}/hooks/{hook_id}/pings` | Ping a webhook |

**Security audit note:** Check for `insecure_ssl: "1"` (allows insecure connections) and verify webhook URLs are HTTPS.

**Permissions:** Repo/org admin. Fine-grained PAT: "Webhooks" repo permission (read/write).

### 2.7 Fork Settings & Visibility

**REST:**

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/repos/{owner}/{repo}` | Response includes `visibility` (public/private/internal), `archived`, `disabled`, `fork`, `forks_count`, `allow_forking` |
| `GET` | `/repos/{owner}/{repo}/forks` | List forks |
| `PATCH` | `/repos/{owner}/{repo}` | Update visibility, archive status, forking |

**GraphQL:**

```graphql
query {
  repository(owner: "OWNER", name: "REPO") {
    visibility       # PUBLIC, PRIVATE, INTERNAL
    isArchived
    isDisabled
    isFork
    forkCount
    forkingAllowed
  }
}
```

### 2.8 Tag Protection Rules

**DEPRECATED** as of August 30, 2024. Migrated to Repository Rulesets (section 2.2 above). The old endpoints `GET/POST/DELETE /repos/{owner}/{repo}/tags/protection` have been removed.

---

## 3. GitHub Advanced Security (GHAS)

### 3.1 Secret Scanning

**REST:**

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/orgs/{org}/secret-scanning/alerts` | List org-wide secret scanning alerts |
| `GET` | `/repos/{owner}/{repo}/secret-scanning/alerts` | List repo secret scanning alerts |
| `GET` | `/repos/{owner}/{repo}/secret-scanning/alerts/{alert_number}` | Get a single alert |
| `PATCH` | `/repos/{owner}/{repo}/secret-scanning/alerts/{alert_number}` | Update alert (resolve/reopen) |
| `GET` | `/repos/{owner}/{repo}/secret-scanning/alerts/{alert_number}/locations` | List alert locations |
| `GET` | `/enterprises/{enterprise}/secret-scanning/alerts` | List enterprise-wide alerts |

**Push Protection:**

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/repos/{owner}/{repo}/secret-scanning/push-protection-bypasses` | Create a push protection bypass |

**Custom Patterns (Enterprise Cloud):**

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/orgs/{org}/secret-scanning/custom-patterns` | List custom patterns |
| `POST` | `/orgs/{org}/secret-scanning/custom-patterns` | Create custom pattern |
| `GET` | `/orgs/{org}/secret-scanning/custom-patterns/{pattern_id}` | Get a pattern |
| `PATCH` | `/orgs/{org}/secret-scanning/custom-patterns/{pattern_id}` | Update a pattern |
| `DELETE` | `/orgs/{org}/secret-scanning/custom-patterns/{pattern_id}` | Delete a pattern |
| `GET` | `/repos/{owner}/{repo}/secret-scanning/custom-patterns` | List repo custom patterns |

**Enable/Disable (via repository settings):**
The `GET /repos/{owner}/{repo}` response includes `security_and_analysis.secret_scanning.status` and `security_and_analysis.secret_scanning_push_protection.status` (`enabled`/`disabled`). Use `PATCH /repos/{owner}/{repo}` to toggle.

**Permissions:** `security_events` scope or `secret_scanning_alerts` permission on fine-grained PAT. Org admin/security manager for org-level endpoints.

### 3.2 Code Scanning

**REST:**

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/orgs/{org}/code-scanning/alerts` | List org-wide code scanning alerts |
| `GET` | `/repos/{owner}/{repo}/code-scanning/alerts` | List repo code scanning alerts |
| `GET` | `/repos/{owner}/{repo}/code-scanning/alerts/{alert_number}` | Get a single alert |
| `PATCH` | `/repos/{owner}/{repo}/code-scanning/alerts/{alert_number}` | Update alert state |
| `GET` | `/repos/{owner}/{repo}/code-scanning/alerts/{alert_number}/instances` | List alert instances |
| `GET` | `/repos/{owner}/{repo}/code-scanning/analyses` | List code scanning analyses |
| `GET` | `/repos/{owner}/{repo}/code-scanning/analyses/{analysis_id}` | Get an analysis |
| `DELETE` | `/repos/{owner}/{repo}/code-scanning/analyses/{analysis_id}` | Delete an analysis |
| `POST` | `/repos/{owner}/{repo}/code-scanning/sarifs` | Upload SARIF data |
| `GET` | `/repos/{owner}/{repo}/code-scanning/sarifs/{sarif_id}` | Get SARIF upload status |
| `GET` | `/repos/{owner}/{repo}/code-scanning/codeql/databases` | List CodeQL databases |
| `GET` | `/repos/{owner}/{repo}/code-scanning/codeql/databases/{language}` | Get a CodeQL database |
| `GET` | `/repos/{owner}/{repo}/code-scanning/default-setup` | Get default CodeQL setup config |
| `PATCH` | `/repos/{owner}/{repo}/code-scanning/default-setup` | Update default CodeQL setup |
| `GET` | `/enterprises/{enterprise}/code-scanning/alerts` | Enterprise-wide alerts |

**Enable/Disable:** `security_and_analysis.advanced_security.status` in repo response.

**Permissions:** `security_events` scope. Fine-grained PAT: "Code scanning alerts" repo permission (read/write).

**Rate limit note:** SARIF uploads have their own dedicated rate limit bucket (`code_scanning_upload` in `/rate_limit` response).

### 3.3 Dependabot

**REST (Alerts):**

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/orgs/{org}/dependabot/alerts` | List org-wide Dependabot alerts |
| `GET` | `/repos/{owner}/{repo}/dependabot/alerts` | List repo Dependabot alerts |
| `GET` | `/repos/{owner}/{repo}/dependabot/alerts/{alert_number}` | Get a single alert |
| `PATCH` | `/repos/{owner}/{repo}/dependabot/alerts/{alert_number}` | Update alert (dismiss/reopen) |
| `GET` | `/enterprises/{enterprise}/dependabot/alerts` | Enterprise-wide alerts |

**REST (Secrets -- repo-level):**

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/repos/{owner}/{repo}/dependabot/secrets` | List repo Dependabot secrets |
| `GET` | `/repos/{owner}/{repo}/dependabot/secrets/{secret_name}` | Get a secret |
| `PUT` | `/repos/{owner}/{repo}/dependabot/secrets/{secret_name}` | Create/update |
| `DELETE` | `/repos/{owner}/{repo}/dependabot/secrets/{secret_name}` | Delete |
| `GET` | `/repos/{owner}/{repo}/dependabot/secrets/public-key` | Get public key |

**Vulnerability Alerts (enable/disable):**

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/repos/{owner}/{repo}/vulnerability-alerts` | Check if enabled (returns 204 or 404) |
| `PUT` | `/repos/{owner}/{repo}/vulnerability-alerts` | Enable vulnerability alerts |
| `DELETE` | `/repos/{owner}/{repo}/vulnerability-alerts` | Disable vulnerability alerts |

**Dependency Graph:**

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/repos/{owner}/{repo}/dependency-graph/sbom` | Export SBOM (SPDX format) |
| `POST` | `/repos/{owner}/{repo}/dependency-graph/snapshots` | Create a dependency snapshot |

**Permissions:** `security_events` scope for alerts. `repo` scope for vulnerability-alerts enable/disable. Fine-grained PAT: "Dependabot alerts" repo permission.

**GraphQL:**

```graphql
query {
  repository(owner: "OWNER", name: "REPO") {
    vulnerabilityAlerts(first: 100) {
      nodes {
        id
        state
        createdAt
        dismissedAt
        fixedAt
        securityAdvisory {
          ghsaId
          summary
          severity
          description
          permalink
          cvss { score vectorString }
          cwes(first: 5) { nodes { cweId name } }
        }
        securityVulnerability {
          package { name ecosystem }
          vulnerableVersionRange
          firstPatchedVersion { identifier }
          severity
        }
        vulnerableManifestPath
        vulnerableManifestFilename
      }
    }
    hasVulnerabilityAlertsEnabled
  }
}
```

### 3.4 Security Advisories

**REST (Repository-level):**

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/repos/{owner}/{repo}/security-advisories` | List repo security advisories |
| `POST` | `/repos/{owner}/{repo}/security-advisories` | Create a draft advisory |
| `GET` | `/repos/{owner}/{repo}/security-advisories/{ghsa_id}` | Get an advisory |
| `PATCH` | `/repos/{owner}/{repo}/security-advisories/{ghsa_id}` | Update an advisory |
| `POST` | `/repos/{owner}/{repo}/security-advisories/{ghsa_id}/cve` | Request CVE ID |
| `POST` | `/repos/{owner}/{repo}/security-advisories/{ghsa_id}/forks` | Create temporary private fork |
| `GET` | `/repos/{owner}/{repo}/security-advisories/reports` | List privately reported advisories |

**REST (Global):**

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/advisories` | List global security advisories |
| `GET` | `/advisories/{ghsa_id}` | Get a global advisory |

**Permissions:** `security_events` scope or repo admin for repo-level. Public for global advisories.

### 3.5 Code Security Configurations (New, replaces per-feature enable/disable)

**REST:**

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/orgs/{org}/code-security/configurations` | List all security configs |
| `POST` | `/orgs/{org}/code-security/configurations` | Create a security config |
| `GET` | `/orgs/{org}/code-security/configurations/{configuration_id}` | Get a config |
| `PATCH` | `/orgs/{org}/code-security/configurations/{configuration_id}` | Update a config |
| `DELETE` | `/orgs/{org}/code-security/configurations/{configuration_id}` | Delete a config |
| `GET` | `/orgs/{org}/code-security/configurations/defaults` | Get default configs |
| `PUT` | `/orgs/{org}/code-security/configurations/defaults` | Set default config |
| `POST` | `/orgs/{org}/code-security/configurations/{configuration_id}/attach` | Attach config to repos |
| `GET` | `/orgs/{org}/code-security/configurations/{configuration_id}/repositories` | List attached repos |

**Note:** This is the replacement for the deprecated `POST /orgs/{org}/{security_product}/{enablement}` endpoint.

**Permissions:** Org owner or security manager. `admin:org` scope.

---

## 4. Access Control

### 4.1 Collaborators and Permissions

**REST:**

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/repos/{owner}/{repo}/collaborators` | List collaborators (includes `role_name` and `permissions` hash) |
| `GET` | `/repos/{owner}/{repo}/collaborators/{username}` | Check if user is collaborator |
| `GET` | `/repos/{owner}/{repo}/collaborators/{username}/permission` | Get user's permission level |
| `PUT` | `/repos/{owner}/{repo}/collaborators/{username}` | Add/update collaborator |
| `DELETE` | `/repos/{owner}/{repo}/collaborators/{username}` | Remove collaborator |

**Response includes:** `role_name` (read, triage, write, maintain, admin, or custom role name), `permissions` hash with `admin`, `maintain`, `push`, `triage`, `pull` booleans.

**Permissions:** Repo admin/write/maintain. Fine-grained PAT: "Members" repo permission (read).

### 4.2 Team Access on Repos

**REST:**

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/repos/{owner}/{repo}/teams` | List teams with access to repo |
| `GET` | `/orgs/{org}/teams/{team_slug}/repos` | List repos for a team |
| `GET` | `/orgs/{org}/teams/{team_slug}/repos/{owner}/{repo}` | Check team permission on repo |
| `PUT` | `/orgs/{org}/teams/{team_slug}/repos/{owner}/{repo}` | Add/update team repo permission |
| `DELETE` | `/orgs/{org}/teams/{team_slug}/repos/{owner}/{repo}` | Remove team from repo |
| `GET` | `/orgs/{org}/teams` | List teams |
| `GET` | `/orgs/{org}/teams/{team_slug}` | Get team details |
| `GET` | `/orgs/{org}/teams/{team_slug}/members` | List team members |

**Permissions:** Repo read access for listing teams. `admin:org` or team maintainer for mutations. Fine-grained PAT: "Members" org permission.

### 4.3 Deploy Keys

**REST:**

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/repos/{owner}/{repo}/keys` | List deploy keys |
| `POST` | `/repos/{owner}/{repo}/keys` | Add a deploy key |
| `GET` | `/repos/{owner}/{repo}/keys/{key_id}` | Get a deploy key |
| `DELETE` | `/repos/{owner}/{repo}/keys/{key_id}` | Remove a deploy key |

**Security audit note:** Check `read_only: false` -- write-access deploy keys are higher risk.

**Permissions:** Repo admin or push access. Fine-grained PAT: "Administration" repo permission (read).

### 4.4 Repository Invitations

**REST:**

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/repos/{owner}/{repo}/invitations` | List pending invitations |
| `PATCH` | `/repos/{owner}/{repo}/invitations/{invitation_id}` | Update invitation |
| `DELETE` | `/repos/{owner}/{repo}/invitations/{invitation_id}` | Delete invitation |
| `GET` | `/user/repository_invitations` | List invitations for authenticated user |

**Permissions:** Repo admin. Fine-grained PAT: "Administration" repo permission (read).

### 4.5 Fine-Grained PAT Management

**REST:**

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/orgs/{org}/personal-access-tokens` | List fine-grained PATs with access to org |
| `POST` | `/orgs/{org}/personal-access-tokens` | Update access for multiple PATs |
| `GET` | `/orgs/{org}/personal-access-tokens/{pat_id}` | Get details of a PAT |
| `POST` | `/orgs/{org}/personal-access-tokens/{pat_id}` | Update access for a PAT |
| `GET` | `/orgs/{org}/personal-access-token-requests` | List pending PAT requests |
| `POST` | `/orgs/{org}/personal-access-token-requests` | Review pending requests (bulk) |
| `POST` | `/orgs/{org}/personal-access-token-requests/{pat_request_id}` | Review a single request |
| `GET` | `/orgs/{org}/personal-access-token-requests/{pat_request_id}/repositories` | List repos requested |

**Permissions:** Org owner. `admin:org` scope. **Enterprise Cloud or org with PAT approval enabled.**

### 4.6 GitHub App Installations per Repo

**REST:**

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/repos/{owner}/{repo}/installation` | Get repo installation for authenticated app |
| `GET` | `/user/installations/{installation_id}/repositories` | List repos accessible to installation |
| `GET` | `/installation/repositories` | List repos accessible to app installation |

**Permissions:** Varies by app permissions.

---

## 5. GitHub Actions

### 5.1 Actions Permissions

**REST:**

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/orgs/{org}/actions/permissions` | Get GitHub Actions permissions for org |
| `PUT` | `/orgs/{org}/actions/permissions` | Set GitHub Actions permissions for org |
| `GET` | `/orgs/{org}/actions/permissions/repositories` | List repos enabled for Actions in org |
| `PUT` | `/orgs/{org}/actions/permissions/repositories` | Set repos enabled for Actions in org |
| `PUT` | `/orgs/{org}/actions/permissions/repositories/{repository_id}` | Enable Actions for a specific repo |
| `DELETE` | `/orgs/{org}/actions/permissions/repositories/{repository_id}` | Disable Actions for a specific repo |
| `GET` | `/orgs/{org}/actions/permissions/selected-actions` | Get allowed actions and reusable workflows for org |
| `PUT` | `/orgs/{org}/actions/permissions/selected-actions` | Set allowed actions for org |
| `GET` | `/orgs/{org}/actions/permissions/workflow` | Get default workflow permissions for org |
| `PUT` | `/orgs/{org}/actions/permissions/workflow` | Set default workflow permissions for org |
| `GET` | `/repos/{owner}/{repo}/actions/permissions` | Get Actions permissions for repo |
| `PUT` | `/repos/{owner}/{repo}/actions/permissions` | Set Actions permissions for repo |
| `GET` | `/repos/{owner}/{repo}/actions/permissions/access` | Get workflow access level for external repos |
| `PUT` | `/repos/{owner}/{repo}/actions/permissions/access` | Set workflow access level |
| `GET` | `/repos/{owner}/{repo}/actions/permissions/selected-actions` | Get allowed actions for repo |
| `PUT` | `/repos/{owner}/{repo}/actions/permissions/selected-actions` | Set allowed actions for repo |
| `GET` | `/repos/{owner}/{repo}/actions/permissions/workflow` | Get default workflow permissions for repo |
| `PUT` | `/repos/{owner}/{repo}/actions/permissions/workflow` | Set default workflow permissions for repo |

**Key response fields for audit:**

- `enabled_repositories` -- `all`, `none`, or `selected`
- `allowed_actions` -- `all`, `local_only`, or `selected`
- `default_workflow_permissions` -- `read` or `write`
- `can_approve_pull_request_reviews` -- boolean (whether GITHUB_TOKEN can approve PRs)

**Security audit note:** `default_workflow_permissions: "write"` is a significant risk. Check that `allowed_actions` is not `all` (allows any marketplace action). Verify `can_approve_pull_request_reviews` is `false`.

**Permissions:** Org/repo admin. Fine-grained PAT: "Administration" org/repo permission.

### 5.2 Workflows

**REST:**

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/repos/{owner}/{repo}/actions/workflows` | List repository workflows |
| `GET` | `/repos/{owner}/{repo}/actions/workflows/{workflow_id}` | Get a workflow |
| `PUT` | `/repos/{owner}/{repo}/actions/workflows/{workflow_id}/disable` | Disable a workflow |
| `PUT` | `/repos/{owner}/{repo}/actions/workflows/{workflow_id}/enable` | Enable a workflow |
| `POST` | `/repos/{owner}/{repo}/actions/workflows/{workflow_id}/dispatches` | Create a workflow dispatch event |
| `GET` | `/repos/{owner}/{repo}/actions/workflows/{workflow_id}/runs` | List workflow runs |

**Permissions:** Repo read access for GET. `actions:write` for mutations. Fine-grained PAT: "Actions" repo permission.

### 5.3 Workflow Runs

**REST:**

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/repos/{owner}/{repo}/actions/runs` | List workflow runs |
| `GET` | `/repos/{owner}/{repo}/actions/runs/{run_id}` | Get a workflow run |
| `DELETE` | `/repos/{owner}/{repo}/actions/runs/{run_id}` | Delete a workflow run |
| `GET` | `/repos/{owner}/{repo}/actions/runs/{run_id}/approvals` | Get reviews for a run |
| `POST` | `/repos/{owner}/{repo}/actions/runs/{run_id}/approve` | Approve a pending run |
| `GET` | `/repos/{owner}/{repo}/actions/runs/{run_id}/attempts/{attempt_number}` | Get a run attempt |
| `GET` | `/repos/{owner}/{repo}/actions/runs/{run_id}/attempts/{attempt_number}/logs` | Download attempt logs |
| `POST` | `/repos/{owner}/{repo}/actions/runs/{run_id}/cancel` | Cancel a run |
| `GET` | `/repos/{owner}/{repo}/actions/runs/{run_id}/logs` | Download run logs |
| `DELETE` | `/repos/{owner}/{repo}/actions/runs/{run_id}/logs` | Delete run logs |
| `POST` | `/repos/{owner}/{repo}/actions/runs/{run_id}/pending_deployments` | Review pending deployments |
| `GET` | `/repos/{owner}/{repo}/actions/runs/{run_id}/pending_deployments` | Get pending deployments |
| `POST` | `/repos/{owner}/{repo}/actions/runs/{run_id}/rerun` | Re-run a workflow |
| `POST` | `/repos/{owner}/{repo}/actions/runs/{run_id}/rerun-failed-jobs` | Re-run failed jobs |

### 5.4 Secrets (Repository-Level)

**REST:**

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/repos/{owner}/{repo}/actions/secrets` | List repo Actions secrets |
| `GET` | `/repos/{owner}/{repo}/actions/secrets/{secret_name}` | Get a secret (metadata only) |
| `PUT` | `/repos/{owner}/{repo}/actions/secrets/{secret_name}` | Create/update a secret |
| `DELETE` | `/repos/{owner}/{repo}/actions/secrets/{secret_name}` | Delete a secret |
| `GET` | `/repos/{owner}/{repo}/actions/secrets/public-key` | Get public key for encryption |

**Permissions:** Repo admin or collaborator. Fine-grained PAT: "Secrets" repo permission.

### 5.5 Variables

**REST:**

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/orgs/{org}/actions/variables` | List org variables |
| `POST` | `/orgs/{org}/actions/variables` | Create org variable |
| `GET` | `/orgs/{org}/actions/variables/{name}` | Get org variable |
| `PATCH` | `/orgs/{org}/actions/variables/{name}` | Update org variable |
| `DELETE` | `/orgs/{org}/actions/variables/{name}` | Delete org variable |
| `GET` | `/repos/{owner}/{repo}/actions/variables` | List repo variables |
| `POST` | `/repos/{owner}/{repo}/actions/variables` | Create repo variable |
| `GET` | `/repos/{owner}/{repo}/actions/variables/{name}` | Get repo variable |
| `PATCH` | `/repos/{owner}/{repo}/actions/variables/{name}` | Update repo variable |
| `DELETE` | `/repos/{owner}/{repo}/actions/variables/{name}` | Delete repo variable |

### 5.6 Environments

**REST:**

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/repos/{owner}/{repo}/environments` | List environments |
| `GET` | `/repos/{owner}/{repo}/environments/{environment_name}` | Get an environment |
| `PUT` | `/repos/{owner}/{repo}/environments/{environment_name}` | Create/update environment |
| `DELETE` | `/repos/{owner}/{repo}/environments/{environment_name}` | Delete environment |
| `GET` | `/repos/{owner}/{repo}/environments/{environment_name}/secrets` | List environment secrets |
| `GET` | `/repos/{owner}/{repo}/environments/{environment_name}/secrets/{secret_name}` | Get environment secret |
| `PUT` | `/repos/{owner}/{repo}/environments/{environment_name}/secrets/{secret_name}` | Create/update env secret |
| `DELETE` | `/repos/{owner}/{repo}/environments/{environment_name}/secrets/{secret_name}` | Delete env secret |
| `GET` | `/repos/{owner}/{repo}/environments/{environment_name}/variables` | List environment variables |
| `POST` | `/repos/{owner}/{repo}/environments/{environment_name}/variables` | Create env variable |
| `GET` | `/repos/{owner}/{repo}/environments/{environment_name}/variables/{name}` | Get env variable |
| `PATCH` | `/repos/{owner}/{repo}/environments/{environment_name}/variables/{name}` | Update env variable |
| `DELETE` | `/repos/{owner}/{repo}/environments/{environment_name}/variables/{name}` | Delete env variable |

**Environment protection rules (in PUT body):**

- `wait_timer` -- minutes to wait before allowing deployments (0-43200)
- `prevent_self_review` -- boolean, prevent the actor that triggered the run from approving
- `reviewers` -- list of users/teams that must approve deployments
- `deployment_branch_policy` -- restrict which branches can deploy (`protected_branches` or `custom_branch_policies`)

**Security audit note:** Check for environments without reviewers (no approval gate), environments without branch restrictions, and environments with `prevent_self_review: false`.

**Permissions:** Repo admin for environment management. Fine-grained PAT: "Environments" repo permission.

### 5.7 Self-Hosted Runners

**REST (Organization):**

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/orgs/{org}/actions/runners` | List org self-hosted runners |
| `GET` | `/orgs/{org}/actions/runners/{runner_id}` | Get a self-hosted runner |
| `DELETE` | `/orgs/{org}/actions/runners/{runner_id}` | Delete a self-hosted runner |
| `GET` | `/orgs/{org}/actions/runners/{runner_id}/labels` | List labels for a runner |
| `POST` | `/orgs/{org}/actions/runners/{runner_id}/labels` | Add labels to runner |
| `PUT` | `/orgs/{org}/actions/runners/{runner_id}/labels` | Set labels for runner |
| `DELETE` | `/orgs/{org}/actions/runners/{runner_id}/labels/{name}` | Remove label from runner |
| `POST` | `/orgs/{org}/actions/runners/registration-token` | Create registration token |
| `POST` | `/orgs/{org}/actions/runners/remove-token` | Create removal token |
| `GET` | `/orgs/{org}/actions/runner-groups` | List runner groups |
| `POST` | `/orgs/{org}/actions/runner-groups` | Create runner group |
| `GET` | `/orgs/{org}/actions/runner-groups/{runner_group_id}` | Get runner group |
| `PATCH` | `/orgs/{org}/actions/runner-groups/{runner_group_id}` | Update runner group |
| `DELETE` | `/orgs/{org}/actions/runner-groups/{runner_group_id}` | Delete runner group |
| `GET` | `/orgs/{org}/actions/runner-groups/{runner_group_id}/repositories` | List repos with access to runner group |
| `PUT` | `/orgs/{org}/actions/runner-groups/{runner_group_id}/repositories` | Set repos for runner group |
| `GET` | `/orgs/{org}/actions/runner-groups/{runner_group_id}/runners` | List runners in group |

**REST (Repository):**

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/repos/{owner}/{repo}/actions/runners` | List repo self-hosted runners |
| `GET` | `/repos/{owner}/{repo}/actions/runners/{runner_id}` | Get a runner |
| `DELETE` | `/repos/{owner}/{repo}/actions/runners/{runner_id}` | Delete a runner |
| `POST` | `/repos/{owner}/{repo}/actions/runners/registration-token` | Create registration token |
| `POST` | `/repos/{owner}/{repo}/actions/runners/remove-token` | Create removal token |

**Security audit note:** Self-hosted runners are high-risk. Check that runner groups restrict which repos can use them. Monitor for repo-level runners on public repos (anyone with write access can run code on them).

**Permissions:** Org/repo admin. Fine-grained PAT: "Administration" org/repo permission.

### 5.8 Artifacts

**REST:**

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/repos/{owner}/{repo}/actions/artifacts` | List artifacts for repo |
| `GET` | `/repos/{owner}/{repo}/actions/artifacts/{artifact_id}` | Get an artifact |
| `DELETE` | `/repos/{owner}/{repo}/actions/artifacts/{artifact_id}` | Delete an artifact |
| `GET` | `/repos/{owner}/{repo}/actions/artifacts/{artifact_id}/{archive_format}` | Download artifact |
| `GET` | `/repos/{owner}/{repo}/actions/runs/{run_id}/artifacts` | List artifacts for a run |

**Permissions:** Repo read access. Fine-grained PAT: "Actions" repo permission (read).

### 5.9 Caches

**REST:**

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/repos/{owner}/{repo}/actions/caches` | List Actions caches |
| `DELETE` | `/repos/{owner}/{repo}/actions/caches/{cache_id}` | Delete a cache |
| `DELETE` | `/repos/{owner}/{repo}/actions/caches?key={key}` | Delete caches by key |
| `GET` | `/repos/{owner}/{repo}/actions/cache/usage` | Get cache usage for repo |
| `GET` | `/orgs/{org}/actions/cache/usage` | Get cache usage for org |
| `GET` | `/orgs/{org}/actions/cache/usage-by-repository` | Get cache usage by repo in org |

**Security audit note:** Cache poisoning is a known attack vector. Audit cache sizes and which branches/workflows produce caches.

**Permissions:** Repo admin for deletion. Fine-grained PAT: "Actions" repo permission.

### 5.10 OIDC (OpenID Connect)

**REST:**

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/orgs/{org}/actions/oidc/customization/sub` | Get OIDC subject claim customization for org |
| `PUT` | `/orgs/{org}/actions/oidc/customization/sub` | Set OIDC subject claim customization for org |
| `GET` | `/repos/{owner}/{repo}/actions/oidc/customization/sub` | Get OIDC subject claim for repo |
| `PUT` | `/repos/{owner}/{repo}/actions/oidc/customization/sub` | Set OIDC subject claim for repo |

**Security audit note:** OIDC subject claim customization defines what claims are included in the JWT token issued to workflows. Misconfigured claims can allow unauthorized access to cloud resources (AWS, Azure, GCP). Verify that subject claims include `repo`, `ref`, `environment`, and `job_workflow_ref` for maximum specificity.

**Permissions:** Org/repo admin. Fine-grained PAT: "Administration" org/repo permission.

---

## 6. Rate Limit Considerations

### Rate Limits by Authentication Method

| Authentication Method | Primary Rate Limit | Notes |
|-----------------------|-------------------|-------|
| Unauthenticated | 60 req/hour | Per IP |
| PAT (classic) | 5,000 req/hour | Per token |
| Fine-grained PAT | 5,000 req/hour | Per token |
| GitHub App installation | 5,000 req/hour base | +50/repo over 20 repos; max 12,500 |
| GitHub App (Enterprise Cloud org) | 15,000 req/hour | Per installation |
| OAuth App | 5,000 req/hour | Per token |

### Secondary Rate Limits

POST/PATCH/PUT/DELETE = 5 points; GET/HEAD/OPTIONS = 1 point. Max ~80 concurrent requests.

### Special Rate Limit Buckets

- `code_scanning_upload` -- separate limit for SARIF uploads
- `graphql` -- 5,000 points/hour (each query costs variable points based on complexity)
- `search` -- 30 req/min (authenticated), 10 req/min (unauthenticated)

### Check Current Limits

```
GET /rate_limit
```

### Best Practices for Auditing at Scale

- Use conditional requests (`If-None-Match` / `If-Modified-Since`) to avoid consuming limits
- Use GraphQL to batch queries (one request can fetch multiple repos)
- Implement exponential backoff on 403/429 responses
- Use the `X-RateLimit-Remaining` and `X-RateLimit-Reset` headers
- Spread requests to avoid bursting
- Cache data instead of polling the API repeatedly

---

## 7. Authentication Comparison

### Classic PAT vs Fine-Grained PAT vs GitHub App

| Feature | Classic PAT | Fine-Grained PAT | GitHub App |
|---------|------------|-------------------|------------|
| **Scope granularity** | Broad scopes (`repo`, `admin:org`) | Per-repository, per-permission | Per-repository, per-permission |
| **Organization control** | None -- org cannot restrict | Org can require approval, set policies | Org installs and controls |
| **Expiration** | Optional (can be permanent) | Required (max 1 year) | Installation tokens expire in 1 hour |
| **User association** | Tied to user | Tied to user | Not tied to user (survives departures) |
| **Enterprise audit** | Limited visibility | Full visibility via PAT management API | Full visibility via installations API |
| **Rate limits** | 5,000/hr | 5,000/hr | 5,000-15,000/hr |
| **GraphQL support** | Full | Limited (REST only for some) | Full |
| **Secret scanning access** | `repo` or `security_events` | `secret_scanning_alerts` (read) | `secret_scanning_alerts` permission |
| **Code scanning access** | `security_events` | `code_scanning_alerts` (read) | `code_scanning_alerts` permission |
| **Branch protection** | `admin:repo_hook`, repo admin | `administration` (read) | `administration` permission |
| **Org audit log** | `admin:org` | Not supported via fine-grained PAT | Not typically available |

### Key Gaps in Fine-Grained PATs

- Cannot access audit log API (requires `admin:org` scope, classic PAT only)
- Cannot access some GraphQL endpoints
- Some enterprise-level endpoints require classic PAT with `admin:enterprise`

### Recommendation for Security Auditing

Use a **GitHub App** for automated auditing (higher rate limits, not tied to individual, granular permissions). Fall back to **classic PAT** for audit log and enterprise-level endpoints that are not yet supported by fine-grained PATs.

---

## 8. Enterprise vs Free/Team API Availability

| Feature | Free | Pro | Team | Enterprise Cloud |
|---------|------|-----|------|-----------------|
| Branch protection REST | Public repos only | Public repos only | All repos | All repos |
| Rulesets | Limited | Limited | Full | Full + org-level |
| Secret scanning alerts | Public repos | Public repos | Public repos | All repos |
| Secret scanning push protection | N/A | N/A | Purchasable add-on | Included (or add-on) |
| Code scanning (CodeQL) | Public repos | Public repos | Purchasable add-on | Included (or add-on) |
| Dependabot alerts | All repos | All repos | All repos | All repos |
| Dependabot security updates | All repos | All repos | All repos | All repos |
| Audit log REST API | N/A | N/A | N/A | Full |
| Audit log GraphQL | N/A | N/A | N/A | Full |
| IP allow list | N/A | N/A | N/A | Full |
| SAML SSO | N/A | N/A | N/A | Full |
| Custom repository roles | N/A | N/A | N/A | Full |
| PAT management API | N/A | N/A | Limited | Full |
| Security configurations API | N/A | N/A | Limited | Full |
| Code security configs | N/A | N/A | Available | Full |
| Enterprise audit log | N/A | N/A | N/A | Full |
| SCIM provisioning | N/A | N/A | N/A | Full |

---

## 9. Octokit SDK Method Mapping

The `@octokit/rest` npm package maps 1:1 to REST endpoints. Key security-related namespaces:

```typescript
import { Octokit } from "@octokit/rest";
const octokit = new Octokit({ auth: "ghp_..." });

// --- Organization ---
octokit.rest.orgs.get({ org })                            // GET /orgs/{org}
octokit.rest.orgs.listMembers({ org, filter: "2fa_disabled" })
octokit.rest.orgs.listOutsideCollaborators({ org })
octokit.rest.orgs.listWebhooks({ org })
octokit.rest.orgs.listAppInstallations({ org })

// --- Branch Protection ---
octokit.rest.repos.getBranchProtection({ owner, repo, branch })
octokit.rest.repos.updateBranchProtection({ owner, repo, branch, ... })
octokit.rest.repos.getCommitSignatureProtection({ owner, repo, branch })

// --- Rulesets ---
octokit.rest.repos.getRepoRulesets({ owner, repo })
octokit.rest.repos.getRepoRuleset({ owner, repo, ruleset_id })
octokit.rest.repos.getOrgRulesets({ org })

// --- Secret Scanning ---
octokit.rest.secretScanning.listAlertsForOrg({ org })
octokit.rest.secretScanning.listAlertsForRepo({ owner, repo })
octokit.rest.secretScanning.getAlert({ owner, repo, alert_number })
octokit.rest.secretScanning.listLocationsForAlert({ owner, repo, alert_number })

// --- Code Scanning ---
octokit.rest.codeScanning.listAlertsForOrg({ org })
octokit.rest.codeScanning.listAlertsForRepo({ owner, repo })
octokit.rest.codeScanning.getAlert({ owner, repo, alert_number })
octokit.rest.codeScanning.listRecentAnalyses({ owner, repo })
octokit.rest.codeScanning.getDefaultSetup({ owner, repo })
octokit.rest.codeScanning.uploadSarif({ owner, repo, commit_sha, ref, sarif })

// --- Dependabot ---
octokit.rest.dependabot.listAlertsForOrg({ org })
octokit.rest.dependabot.listAlertsForRepo({ owner, repo })
octokit.rest.dependabot.getAlert({ owner, repo, alert_number })
octokit.rest.dependabot.listOrgSecrets({ org })
octokit.rest.dependabot.listRepoSecrets({ owner, repo })

// --- Collaborators & Access ---
octokit.rest.repos.listCollaborators({ owner, repo })
octokit.rest.repos.getCollaboratorPermissionLevel({ owner, repo, username })
octokit.rest.repos.listTeams({ owner, repo })
octokit.rest.repos.listDeployKeys({ owner, repo })
octokit.rest.repos.listInvitations({ owner, repo })
octokit.rest.repos.listWebhooks({ owner, repo })

// --- Security Advisories ---
octokit.rest.securityAdvisories.listRepositoryAdvisories({ owner, repo })
octokit.rest.securityAdvisories.listGlobalAdvisories()

// --- Vulnerability Alerts ---
octokit.rest.repos.checkVulnerabilityAlerts({ owner, repo })
octokit.rest.repos.enableVulnerabilityAlerts({ owner, repo })

// --- Actions Secrets ---
octokit.rest.actions.listOrgSecrets({ org })
octokit.rest.actions.listRepoSecrets({ owner, repo })

// --- Actions Permissions ---
octokit.rest.actions.getGithubActionsPermissionsOrganization({ org })
octokit.rest.actions.getGithubActionsPermissionsRepository({ owner, repo })
octokit.rest.actions.getGithubActionsDefaultWorkflowPermissionsOrganization({ org })
octokit.rest.actions.getGithubActionsDefaultWorkflowPermissionsRepository({ owner, repo })
octokit.rest.actions.getAllowedActionsOrganization({ org })
octokit.rest.actions.getAllowedActionsRepository({ owner, repo })

// --- Actions Runners ---
octokit.rest.actions.listSelfHostedRunnersForOrg({ org })
octokit.rest.actions.listSelfHostedRunnersForRepo({ owner, repo })
octokit.rest.actions.listRunnerGroupsForOrg({ org })

// --- Actions Workflows ---
octokit.rest.actions.listRepoWorkflows({ owner, repo })
octokit.rest.actions.listWorkflowRuns({ owner, repo, workflow_id })
octokit.rest.actions.listWorkflowRunsForRepo({ owner, repo })

// --- Environments ---
octokit.rest.repos.getAllEnvironments({ owner, repo })
octokit.rest.repos.getEnvironment({ owner, repo, environment_name })
octokit.rest.actions.listEnvironmentSecrets({ owner, repo, environment_name })
octokit.rest.actions.listEnvironmentVariables({ owner, repo, environment_name })

// --- Actions OIDC ---
octokit.rest.oidc.getOidcCustomSubTemplateForOrg({ org })
octokit.rest.oidc.updateOidcCustomSubTemplateForOrg({ org, include_claim_keys })

// --- Actions Caches ---
octokit.rest.actions.getActionsCacheList({ owner, repo })
octokit.rest.actions.getActionsCacheUsage({ owner, repo })
octokit.rest.actions.getActionsCacheUsageForOrg({ org })

// --- Community / CODEOWNERS ---
octokit.rest.repos.getCommunityProfileMetrics({ owner, repo })
octokit.rest.repos.getContent({ owner, repo, path: "CODEOWNERS" })
octokit.rest.repos.listCodeownersErrors({ owner, repo })

// --- Audit Log (classic PAT only) ---
octokit.rest.orgs.getAuditLog({ org, phrase, include, per_page })

// --- PAT Management ---
octokit.rest.orgs.listPatGrantRequests({ org })
octokit.rest.orgs.listPatGrants({ org })
```

For GraphQL, use `@octokit/graphql`:

```typescript
import { graphql } from "@octokit/graphql";
const graphqlWithAuth = graphql.defaults({
  headers: { authorization: "token ghp_..." }
});

const result = await graphqlWithAuth(`
  query($org: String!) {
    organization(login: $org) {
      repositories(first: 100) {
        nodes {
          name
          branchProtectionRules(first: 10) {
            nodes { pattern isAdminEnforced requiresApprovingReviews }
          }
          vulnerabilityAlerts(first: 10) {
            nodes { state securityAdvisory { severity summary } }
          }
          hasVulnerabilityAlertsEnabled
          isSecurityPolicyEnabled
          securityPolicyUrl
        }
      }
    }
  }
`, { org: "my-org" });
```

---

## 10. Beta/Preview APIs and Undocumented Endpoints

1. **Audit Log Streaming REST API** -- Private beta (announced July 2024). Enterprise owners can configure audit log streaming destinations via REST API instead of the UI only.

2. **Secret Scanning Dismissal Requests** -- Added April 2025. `GET/PATCH` endpoints for managing alert dismissal requests when org requires review before dismissal.

3. **Secret Scanning `first_location_detected` and `has_more_locations`** -- GA as of June 2025. New response fields showing where a secret was first detected and whether it appears in multiple locations.

4. **Code Security Configurations API** -- GA as of mid-2024. Replaces the deprecated per-feature enablement API (`POST /orgs/{org}/{security_product}/{enablement}`).

5. **Repository Properties API** -- `GET/PUT /orgs/{org}/properties/schema`, `GET /repos/{owner}/{repo}/properties/values`. Custom properties for repos that can be used in ruleset targeting.

6. **Copilot Metrics API** -- `GET /orgs/{org}/copilot/usage`, `GET /orgs/{org}/copilot/billing/seats`. Not directly security but useful for auditing Copilot access.

7. **Repository Advisories `reports` endpoint** -- `GET /repos/{owner}/{repo}/security-advisories/reports` for privately reported vulnerabilities.

---

## Sources

- [REST API endpoints for organizations](https://docs.github.com/en/rest/orgs/orgs)
- [REST API endpoints for protected branches](https://docs.github.com/en/rest/branches/branch-protection)
- [REST API endpoints for rules (rulesets)](https://docs.github.com/en/rest/repos/rules)
- [REST API endpoints for secret scanning](https://docs.github.com/en/rest/secret-scanning/secret-scanning)
- [REST API endpoints for code scanning](https://docs.github.com/en/rest/code-scanning/code-scanning)
- [REST API endpoints for Dependabot alerts](https://docs.github.com/en/rest/dependabot/alerts)
- [REST API endpoints for Dependabot secrets](https://docs.github.com/en/rest/dependabot/secrets)
- [REST API endpoints for code security configurations](https://docs.github.com/en/rest/code-security/configurations)
- [REST API endpoints for collaborators](https://docs.github.com/en/rest/collaborators/collaborators)
- [REST API endpoints for deploy keys](https://docs.github.com/en/rest/deploy-keys/deploy-keys)
- [REST API endpoints for repository webhooks](https://docs.github.com/en/rest/repos/webhooks)
- [REST API endpoints for organization webhooks](https://docs.github.com/en/rest/orgs/webhooks)
- [REST API endpoints for repository security advisories](https://docs.github.com/en/rest/security-advisories/repository-advisories)
- [REST API endpoints for community metrics](https://docs.github.com/en/rest/metrics/community)
- [REST API endpoints for GitHub App installations](https://docs.github.com/en/rest/apps/installations)
- [REST API endpoints for organization roles](https://docs.github.com/en/rest/orgs/organization-roles)
- [REST API endpoints for security managers](https://docs.github.com/en/rest/orgs/security-managers)
- [REST API endpoints for GitHub Actions permissions](https://docs.github.com/en/rest/actions/permissions)
- [REST API endpoints for GitHub Actions secrets](https://docs.github.com/en/rest/actions/secrets)
- [REST API endpoints for self-hosted runners](https://docs.github.com/en/rest/actions/self-hosted-runners)
- [REST API endpoints for environments](https://docs.github.com/en/rest/deployments/environments)
- [REST API endpoints for GitHub Actions artifacts](https://docs.github.com/en/rest/actions/artifacts)
- [REST API endpoints for GitHub Actions cache](https://docs.github.com/en/rest/actions/cache)
- [REST API endpoints for GitHub Actions OIDC](https://docs.github.com/en/rest/actions/oidc)
- [REST API endpoints for GitHub Actions workflows](https://docs.github.com/en/rest/actions/workflows)
- [REST API endpoints for workflow runs](https://docs.github.com/en/rest/actions/workflow-runs)
- [Rate limits for the REST API](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api)
- [Permissions required for fine-grained PATs](https://docs.github.com/en/rest/authentication/permissions-required-for-fine-grained-personal-access-tokens)
- [Enterprise audit log API](https://docs.github.com/en/enterprise-cloud@latest/rest/enterprise-admin/audit-log)
