import type { CheckResult } from "../types/index.js";
import type { GitHubClientFactory } from "../github/client.js";

/**
 * ORG-001: 2FA requirement enforcement
 * ORG-002: Default repository permission level
 * ORG-003: Public repo creation by members
 */
export async function checkOrgSecurity(
  client: GitHubClientFactory,
  args: Record<string, unknown>,
): Promise<CheckResult[]> {
  const org = args.org as string;
  const results: CheckResult[] = [];

  try {
    const { data } = await client.rest().orgs.get({ org });

    // ORG-001: Two-factor authentication not enforced
    results.push({
      checkId: "ORG-001",
      title: "Two-factor authentication not enforced",
      severity: "CRITICAL",
      status: data.two_factor_requirement_enabled ? "PASS" : "FAIL",
      resource: `org/${org}`,
      category: "org",
      details: data.two_factor_requirement_enabled
        ? `Organization '${org}' enforces two-factor authentication for all members.`
        : `Organization '${org}' does NOT enforce two-factor authentication. Any member can join without 2FA, leaving the organization vulnerable to credential theft and account takeover.`,
      remediation:
        "Go to Organization Settings > Authentication security > Require two-factor authentication for everyone in the organization.",
      reference:
        "https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-two-factor-authentication-for-your-organization/requiring-two-factor-authentication-in-your-organization",
    });

    // ORG-002: Default repository permission too permissive
    const defaultPerm = data.default_repository_permission ?? "read";
    const isRestrictive = defaultPerm === "none" || defaultPerm === "read";
    results.push({
      checkId: "ORG-002",
      title: "Default repository permission too permissive",
      severity: "HIGH",
      status: isRestrictive ? "PASS" : "FAIL",
      resource: `org/${org}`,
      category: "org",
      details: isRestrictive
        ? `Organization '${org}' default repository permission is '${defaultPerm}' (acceptable).`
        : `Organization '${org}' default repository permission is '${defaultPerm}'. Members get ${defaultPerm} access to ALL repositories by default, violating least-privilege principle.`,
      remediation:
        "Go to Organization Settings > Member privileges > Base permissions and set to 'No permission' or 'Read'.",
      reference:
        "https://docs.github.com/en/organizations/managing-user-access-to-your-organizations-repositories/managing-repository-roles/setting-base-permissions-for-an-organization",
    });

    // ORG-003: Members can create public repositories
    const canCreatePublic = data.members_can_create_public_repositories ?? true;
    results.push({
      checkId: "ORG-003",
      title: "Members can create public repositories",
      severity: "MEDIUM",
      status: canCreatePublic ? "FAIL" : "PASS",
      resource: `org/${org}`,
      category: "org",
      details: canCreatePublic
        ? `Organization '${org}' allows members to create public repositories. This increases the risk of accidental source code or secret exposure.`
        : `Organization '${org}' restricts members from creating public repositories.`,
      remediation:
        "Go to Organization Settings > Member privileges > Repository creation and uncheck 'Public'.",
      reference:
        "https://docs.github.com/en/organizations/managing-organization-settings/restricting-repository-creation-in-your-organization",
    });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    results.push({
      checkId: "ORG-001",
      title: "Two-factor authentication not enforced",
      severity: "CRITICAL",
      status: "ERROR",
      resource: `org/${org}`,
      category: "org",
      details: `Failed to retrieve organization settings for '${org}': ${message}`,
      remediation: "Verify the token has org:read scope and the organization name is correct.",
    });
  }

  return results;
}
