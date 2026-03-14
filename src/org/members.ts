import type { CheckResult } from "../types/index.js";
import type { GitHubClientFactory } from "../github/client.js";

/**
 * ORG-005: Outside collaborators present
 * ORG-006: Organization member count (informational)
 */
export async function checkOrgMembers(
  client: GitHubClientFactory,
  args: Record<string, unknown>,
): Promise<CheckResult[]> {
  const org = args.org as string;
  const results: CheckResult[] = [];

  // ORG-005: Outside collaborators
  try {
    const { data: collaborators } = await client
      .rest()
      .orgs.listOutsideCollaborators({ org, per_page: 100 });

    const count = collaborators.length;
    const logins = collaborators
      .slice(0, 10)
      .map((c) => c.login)
      .join(", ");

    results.push({
      checkId: "ORG-005",
      title: "Outside collaborators detected",
      severity: "MEDIUM",
      status: count > 0 ? "FAIL" : "PASS",
      resource: `org/${org}`,
      category: "org",
      details:
        count > 0
          ? `Organization '${org}' has ${count} outside collaborator(s). ${count <= 10 ? `Users: ${logins}` : `First 10: ${logins} (and ${count - 10} more)`}. Outside collaborators bypass organization-level policies such as 2FA and SSO requirements.`
          : `Organization '${org}' has no outside collaborators.`,
      remediation:
        "Review outside collaborators and convert them to organization members where appropriate. Go to Organization Settings > People > Outside collaborators.",
      reference:
        "https://docs.github.com/en/organizations/managing-user-access-to-your-organizations-repositories/managing-outside-collaborators/adding-outside-collaborators-to-repositories-in-your-organization",
    });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    results.push({
      checkId: "ORG-005",
      title: "Outside collaborators detected",
      severity: "MEDIUM",
      status: "ERROR",
      resource: `org/${org}`,
      category: "org",
      details: `Failed to list outside collaborators for '${org}': ${message}`,
      remediation:
        "Verify the token has org:read scope and the organization name is correct.",
    });
  }

  // ORG-006: Member count (informational)
  try {
    const { data: members } = await client
      .rest()
      .orgs.listMembers({ org, per_page: 100 });

    const count = members.length;
    const hasMore = count === 100;

    results.push({
      checkId: "ORG-006",
      title: "Organization member inventory",
      severity: "LOW",
      status: "PASS",
      resource: `org/${org}`,
      category: "org",
      details: hasMore
        ? `Organization '${org}' has 100+ members (paginated, showing first page). Consider auditing member access regularly.`
        : `Organization '${org}' has ${count} member(s). Regular access reviews are recommended.`,
      remediation:
        "Periodically review organization membership. Remove inactive members and ensure each member has appropriate access levels.",
      reference:
        "https://docs.github.com/en/organizations/managing-membership-in-your-organization/removing-a-member-from-your-organization",
    });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    results.push({
      checkId: "ORG-006",
      title: "Organization member inventory",
      severity: "LOW",
      status: "ERROR",
      resource: `org/${org}`,
      category: "org",
      details: `Failed to list members for '${org}': ${message}`,
      remediation:
        "Verify the token has org:read scope and the organization name is correct.",
    });
  }

  return results;
}
