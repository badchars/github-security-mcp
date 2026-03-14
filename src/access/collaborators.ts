import type { CheckResult } from "../types/index.js";
import type { GitHubClientFactory } from "../github/client.js";

/**
 * ACC-002: External collaborators with elevated permissions check.
 * Flags outside collaborators who have write, maintain, or admin access.
 */
export async function checkCollaborators(
  client: GitHubClientFactory,
  args: Record<string, unknown>,
): Promise<CheckResult[]> {
  const owner = args.owner as string;
  const repo = args.repo as string;
  const results: CheckResult[] = [];
  const resource = `${owner}/${repo}`;

  try {
    const { data: collaborators } = await client.rest().repos.listCollaborators({
      owner,
      repo,
      affiliation: "outside",
      per_page: 100,
    });

    if (collaborators.length === 0) {
      results.push({
        checkId: "ACC-002",
        title: "No external collaborators",
        severity: "MEDIUM",
        status: "PASS",
        resource,
        category: "access",
        details: "No outside collaborators have access to this repository.",
        remediation: "No action needed.",
        reference: "https://docs.github.com/en/organizations/managing-user-access-to-your-organizations-repositories/adding-outside-collaborators-to-repositories-in-your-organization",
      });
      return results;
    }

    const elevatedPerms = ["push", "maintain", "admin"];
    const riskyCollaborators = collaborators.filter((c) => {
      const perms = c.permissions;
      if (!perms) return false;
      return perms.admin || perms.maintain || perms.push;
    });

    if (riskyCollaborators.length > 0) {
      const collabList = riskyCollaborators
        .map((c) => {
          const perms = c.permissions;
          const permLevel = perms?.admin ? "admin" : perms?.maintain ? "maintain" : "write";
          return `- ${c.login} (permission: ${permLevel})`;
        })
        .join("\n");

      results.push({
        checkId: "ACC-002",
        title: "External collaborators with elevated access",
        severity: "MEDIUM",
        status: "FAIL",
        resource,
        category: "access",
        details: `Found ${riskyCollaborators.length} outside collaborator(s) with write or higher access (out of ${collaborators.length} total external collaborators).\n\nElevated access collaborators:\n${collabList}`,
        remediation: "Review outside collaborators with elevated permissions. Downgrade to read-only access where write access is not necessary. Remove collaborators who no longer need access. Settings > Collaborators and teams.",
        reference: "https://docs.github.com/en/organizations/managing-user-access-to-your-organizations-repositories/adding-outside-collaborators-to-repositories-in-your-organization",
      });
    } else {
      results.push({
        checkId: "ACC-002",
        title: "External collaborators have read-only access",
        severity: "MEDIUM",
        status: "PASS",
        resource,
        category: "access",
        details: `Found ${collaborators.length} outside collaborator(s), all with read-only access.`,
        remediation: "No action needed.",
        reference: "https://docs.github.com/en/organizations/managing-user-access-to-your-organizations-repositories/adding-outside-collaborators-to-repositories-in-your-organization",
      });
    }
  } catch (err: any) {
    if (err.status === 404 || err.status === 403) {
      results.push({
        checkId: "ACC-002",
        title: "Collaborators check not accessible",
        severity: "MEDIUM",
        status: "NOT_APPLICABLE",
        resource,
        category: "access",
        details: `Cannot access collaborator information (HTTP ${err.status}). The repository may not be organization-owned, or the token lacks the required scope. The 'affiliation: outside' filter only works for organization-owned repositories.`,
        remediation: "Ensure the token has repo scope and the repository belongs to an organization.",
        reference: "https://docs.github.com/en/organizations/managing-user-access-to-your-organizations-repositories/adding-outside-collaborators-to-repositories-in-your-organization",
      });
    } else {
      results.push({
        checkId: "ACC-002",
        title: "Collaborators check failed",
        severity: "MEDIUM",
        status: "ERROR",
        resource,
        category: "access",
        details: `Failed to check collaborators: ${err.message}`,
        remediation: "Ensure the token has repo scope.",
      });
    }
  }

  return results;
}
