import type { CheckMeta, CheckCategory, Severity } from "../types/index.js";

const CHECK_REGISTRY: CheckMeta[] = [
  // ═══ Organization ═══
  { id: "ORG-001", category: "org", title: "2FA not enforced for organization", severity: "CRITICAL", description: "Check if two-factor authentication is required for all organization members", references: ["https://docs.github.com/en/organizations/keeping-your-organization-secure/requiring-two-factor-authentication-in-your-organization"] },
  { id: "ORG-002", category: "org", title: "Default repository visibility is public", severity: "HIGH", description: "Check organization default repository permission and visibility settings", references: ["https://docs.github.com/en/organizations/managing-organization-settings/restricting-repository-visibility-changes-in-your-organization"] },
  { id: "ORG-003", category: "org", title: "Members can create public repositories", severity: "MEDIUM", description: "Check if organization members are allowed to create public repositories", references: ["https://docs.github.com/en/organizations/managing-organization-settings/restricting-repository-creation-in-your-organization"] },
  { id: "ORG-004", category: "org", title: "SSO/SAML not configured", severity: "HIGH", description: "Check if SAML single sign-on is configured for the organization", references: ["https://docs.github.com/en/organizations/managing-saml-single-sign-on-for-your-organization"] },
  { id: "ORG-005", category: "org", title: "Outside collaborators with repository access", severity: "MEDIUM", description: "Audit outside collaborators who have access to organization repositories", references: ["https://docs.github.com/en/organizations/managing-user-access-to-your-organizations-repositories/managing-outside-collaborators"] },
  { id: "ORG-006", category: "org", title: "Organization member audit", severity: "LOW", description: "Review organization members for stale or inactive accounts", references: [] },
  { id: "ORG-007", category: "org", title: "Risky OAuth app credential authorizations", severity: "HIGH", description: "Review OAuth application authorizations for the organization", references: ["https://docs.github.com/en/organizations/managing-oauth-access-to-your-organizations-data"] },
  { id: "ORG-008", category: "org", title: "Over-permissive GitHub App installations", severity: "HIGH", description: "Audit GitHub App installations for overly broad permissions", references: ["https://docs.github.com/en/organizations/managing-programmatic-access-to-your-organization"] },
  { id: "ORG-009", category: "org", title: "Insecure webhook URLs (HTTP)", severity: "MEDIUM", description: "Check organization webhooks for insecure HTTP URLs and SSL verification", references: ["https://docs.github.com/en/webhooks/using-webhooks/best-practices-for-using-webhooks"] },
  { id: "ORG-010", category: "org", title: "Suspicious audit log activity", severity: "INFO", description: "Review audit log for suspicious or high-risk events", references: ["https://docs.github.com/en/organizations/keeping-your-organization-secure/reviewing-the-audit-log-for-your-organization"] },

  // ═══ Repository ═══
  { id: "REPO-001", category: "repo", title: "Missing or weak branch protection on default branch", severity: "CRITICAL", description: "Check branch protection rules for required reviews, status checks, and admin enforcement", references: ["https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-a-branch-protection-rule"] },
  { id: "REPO-002", category: "repo", title: "Secret scanning not enabled", severity: "HIGH", description: "Check if GitHub secret scanning is enabled for the repository", references: ["https://docs.github.com/en/code-security/secret-scanning/introduction/about-secret-scanning"] },
  { id: "REPO-003", category: "repo", title: "Push protection not enabled", severity: "HIGH", description: "Check if secret scanning push protection is enabled to prevent secret commits", references: ["https://docs.github.com/en/code-security/secret-scanning/push-protection-for-repositories-and-organizations"] },
  { id: "REPO-004", category: "repo", title: "Code scanning (CodeQL) not configured", severity: "MEDIUM", description: "Check if code scanning with CodeQL or other tools is configured", references: ["https://docs.github.com/en/code-security/code-scanning/introduction-to-code-scanning/about-code-scanning"] },
  { id: "REPO-005", category: "repo", title: "Open code scanning alerts", severity: "HIGH", description: "Check for unresolved code scanning alerts with high or critical severity", references: ["https://docs.github.com/en/code-security/code-scanning/managing-code-scanning-alerts"] },
  { id: "REPO-006", category: "repo", title: "Dependabot security updates not enabled", severity: "MEDIUM", description: "Check if Dependabot security updates are enabled for automatic patching", references: ["https://docs.github.com/en/code-security/dependabot/dependabot-security-updates"] },
  { id: "REPO-007", category: "repo", title: "Critical Dependabot alerts open", severity: "CRITICAL", description: "Check for open Dependabot alerts with critical severity", references: ["https://docs.github.com/en/code-security/dependabot/dependabot-alerts"] },
  { id: "REPO-008", category: "repo", title: "No security policy (SECURITY.md)", severity: "LOW", description: "Check if repository has a security policy for vulnerability reporting", references: ["https://docs.github.com/en/code-security/getting-started/adding-a-security-policy-to-your-repository"] },
  { id: "REPO-009", category: "repo", title: "Private vulnerability reporting disabled", severity: "LOW", description: "Check if private vulnerability reporting is enabled", references: ["https://docs.github.com/en/code-security/security-advisories/working-with-repository-security-advisories"] },
  { id: "REPO-010", category: "repo", title: "Unrestricted fork settings", severity: "LOW", description: "Check if forking is unrestricted for private repositories", references: [] },
  { id: "REPO-011", category: "repo", title: "Insecure webhook URLs", severity: "MEDIUM", description: "Check repository webhooks for insecure HTTP URLs", references: ["https://docs.github.com/en/webhooks/using-webhooks/best-practices-for-using-webhooks"] },
  { id: "REPO-012", category: "repo", title: "Read-write deploy keys", severity: "HIGH", description: "Audit deploy keys for unnecessary write access", references: ["https://docs.github.com/en/authentication/connecting-to-github-with-ssh/managing-deploy-keys"] },
  { id: "REPO-013", category: "repo", title: "Missing CODEOWNERS file", severity: "LOW", description: "Check if CODEOWNERS file exists for code review enforcement", references: ["https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners"] },

  // ═══ Actions ═══
  { id: "ACT-001", category: "actions", title: "Script injection via untrusted inputs", severity: "CRITICAL", description: "Detect workflow run blocks that interpolate untrusted event data (github.event.issue.title, etc.)", references: ["https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections"] },
  { id: "ACT-002", category: "actions", title: "pull_request_target with checkout of PR head", severity: "CRITICAL", description: "Detect dangerous pull_request_target + checkout pattern enabling arbitrary code execution from forks", references: ["https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/"] },
  { id: "ACT-003", category: "actions", title: "Over-permissive GITHUB_TOKEN defaults", severity: "HIGH", description: "Check if repository default workflow permissions are set to write instead of read", references: ["https://docs.github.com/en/actions/security-for-github-actions/security-guides/automatic-token-authentication#modifying-the-permissions-for-the-github_token"] },
  { id: "ACT-004", category: "actions", title: "Unpinned third-party actions", severity: "MEDIUM", description: "Detect third-party actions referenced by tag instead of SHA hash", references: ["https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#using-third-party-actions"] },
  { id: "ACT-005", category: "actions", title: "Self-hosted runners exposed", severity: "HIGH", description: "Detect self-hosted runners that may be at risk of persistence attacks", references: ["https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#hardening-for-self-hosted-runners"] },
  { id: "ACT-006", category: "actions", title: "Missing environment protection rules", severity: "MEDIUM", description: "Check deployment environments for missing protection rules (reviewers, wait timers, branch policies)", references: ["https://docs.github.com/en/actions/managing-workflow-runs-and-deployments/managing-deployments/managing-environments-for-deployment"] },
  { id: "ACT-007", category: "actions", title: "Secret exfiltration patterns in workflows", severity: "HIGH", description: "Detect patterns where secrets are passed to network commands or logged", references: ["https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#using-secrets"] },
  { id: "ACT-008", category: "actions", title: "OIDC misconfiguration", severity: "MEDIUM", description: "Check OIDC subject claim customization for overly broad trust", references: ["https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/about-security-hardening-with-openid-connect"] },

  // ═══ Secrets ═══
  { id: "SEC-001", category: "secrets", title: "Secret scanning coverage gaps", severity: "HIGH", description: "Check if secret scanning is enabled and covering the repository", references: ["https://docs.github.com/en/code-security/secret-scanning"] },
  { id: "SEC-002", category: "secrets", title: "Unresolved secret scanning alerts", severity: "CRITICAL", description: "Check for open secret scanning alerts that have not been resolved", references: ["https://docs.github.com/en/code-security/secret-scanning/managing-alerts-from-secret-scanning"] },
  { id: "SEC-003", category: "secrets", title: "Push protection bypasses detected", severity: "HIGH", description: "Check for secret scanning alerts where push protection was bypassed", references: ["https://docs.github.com/en/code-security/secret-scanning/push-protection-for-repositories-and-organizations"] },
  { id: "SEC-004", category: "secrets", title: "No custom secret scanning patterns", severity: "LOW", description: "Check if organization has defined custom secret scanning patterns", references: ["https://docs.github.com/en/code-security/secret-scanning/using-advanced-secret-scanning-and-push-protection-features/custom-patterns"] },
  { id: "SEC-005", category: "secrets", title: "Overly broad secret scoping", severity: "MEDIUM", description: "Review secret scoping across environments, repositories, and organization levels", references: ["https://docs.github.com/en/actions/security-for-github-actions/security-guides/using-secrets-in-github-actions"] },

  // ═══ Supply Chain ═══
  { id: "SUP-001", category: "supply-chain", title: "Dependency graph not enabled", severity: "MEDIUM", description: "Check if the dependency graph is enabled for vulnerability detection", references: ["https://docs.github.com/en/code-security/supply-chain-security/understanding-your-software-supply-chain/about-the-dependency-graph"] },
  { id: "SUP-002", category: "supply-chain", title: "Dependabot security updates disabled", severity: "HIGH", description: "Check if Dependabot automated security updates are enabled", references: ["https://docs.github.com/en/code-security/dependabot/dependabot-security-updates"] },
  { id: "SUP-003", category: "supply-chain", title: "No SBOM generation configured", severity: "LOW", description: "Check if software bill of materials can be generated from the dependency graph", references: ["https://docs.github.com/en/code-security/supply-chain-security/understanding-your-software-supply-chain/exporting-a-software-bill-of-materials-for-your-repository"] },
  { id: "SUP-004", category: "supply-chain", title: "Critical known vulnerabilities in dependencies", severity: "CRITICAL", description: "Check for open Dependabot alerts with critical severity", references: ["https://docs.github.com/en/code-security/dependabot/dependabot-alerts"] },
  { id: "SUP-005", category: "supply-chain", title: "Stale unfixed vulnerabilities (>90 days)", severity: "HIGH", description: "Check for Dependabot alerts that have been open for more than 90 days", references: [] },

  // ═══ Access Control ═══
  { id: "ACC-001", category: "access", title: "Over-permissive team access", severity: "HIGH", description: "Audit team permissions for admin-level access to repositories", references: ["https://docs.github.com/en/organizations/managing-user-access-to-your-organizations-repositories/managing-repository-roles/repository-roles-for-an-organization"] },
  { id: "ACC-002", category: "access", title: "External collaborators with write access", severity: "MEDIUM", description: "Check for outside collaborators with push, maintain, or admin permissions", references: ["https://docs.github.com/en/organizations/managing-user-access-to-your-organizations-repositories/managing-outside-collaborators"] },
  { id: "ACC-003", category: "access", title: "Over-scoped GitHub App permissions", severity: "HIGH", description: "Audit GitHub App installations for overly broad permission scopes", references: ["https://docs.github.com/en/apps/using-github-apps/reviewing-and-modifying-installed-github-apps"] },
  { id: "ACC-004", category: "access", title: "Classic PATs with broad scopes", severity: "HIGH", description: "Check for classic personal access tokens with overly broad scopes", references: ["https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens"] },
];

export function listChecks(args: {
  category?: string;
  severity?: string;
}): CheckMeta[] {
  let checks: CheckMeta[] = CHECK_REGISTRY;

  if (args.category) {
    checks = checks.filter(c => c.category === args.category);
  }
  if (args.severity) {
    const sev = args.severity.toUpperCase();
    checks = checks.filter(c => c.severity === sev);
  }

  return checks;
}

export function getCheckMeta(checkId: string): CheckMeta | undefined {
  return CHECK_REGISTRY.find(c => c.id === checkId);
}

export { CHECK_REGISTRY };
