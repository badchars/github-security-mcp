import type { CheckResult } from "../types/index.js";
import type { GitHubClientFactory } from "../github/client.js";

/**
 * ACC-001: Over-permissive team access check.
 * If a repo is provided, checks teams with admin access on that repo.
 * If only org is provided, lists all teams and their permission levels.
 */
export async function checkTeamPermissions(
  client: GitHubClientFactory,
  args: Record<string, unknown>,
): Promise<CheckResult[]> {
  const org = args.org as string;
  const repo = args.repo as string | undefined;
  const results: CheckResult[] = [];
  const resource = repo ? `${org}/${repo}` : org;

  if (repo) {
    // Repo-scoped check: find teams with admin access
    try {
      const { data: teams } = await client.rest().repos.listTeams({
        owner: org,
        repo,
        per_page: 100,
      });

      if (teams.length === 0) {
        results.push({
          checkId: "ACC-001",
          title: "No teams have access to this repository",
          severity: "HIGH",
          status: "PASS",
          resource,
          category: "access",
          details: "No teams are assigned to this repository. Access is managed through direct collaborators.",
          remediation: "No action needed. Consider using team-based access for better manageability.",
          reference: "https://docs.github.com/en/organizations/managing-user-access-to-your-organizations-repositories/managing-team-access-to-an-organization-repository",
        });
        return results;
      }

      const adminTeams = teams.filter((t) => t.permission === "admin");
      const maintainTeams = teams.filter((t) => t.permission === "maintain");
      const pushTeams = teams.filter((t) => t.permission === "push");
      const pullTeams = teams.filter((t) => t.permission === "pull");

      if (adminTeams.length > 0) {
        const teamList = adminTeams
          .map((t) => `- ${t.name} (slug: ${t.slug}, members: ${(t as any).members_count ?? "unknown"})`)
          .join("\n");

        results.push({
          checkId: "ACC-001",
          title: "Teams with admin access found",
          severity: "HIGH",
          status: "FAIL",
          resource,
          category: "access",
          details: `Found ${adminTeams.length} team(s) with admin access to this repository. Admin access grants full control including settings, branch protection overrides, and destructive actions.\n\nAdmin teams:\n${teamList}\n\nPermission breakdown: ${adminTeams.length} admin, ${maintainTeams.length} maintain, ${pushTeams.length} write, ${pullTeams.length} read (${teams.length} total).`,
          remediation: "Review teams with admin access. Downgrade to 'maintain' or 'write' permission where full admin is not required. Limit admin access to infrastructure/platform teams only.",
          reference: "https://docs.github.com/en/organizations/managing-user-access-to-your-organizations-repositories/managing-team-access-to-an-organization-repository",
        });
      } else {
        results.push({
          checkId: "ACC-001",
          title: "No teams with admin access",
          severity: "HIGH",
          status: "PASS",
          resource,
          category: "access",
          details: `${teams.length} team(s) have access but none have admin permission. Permission breakdown: ${maintainTeams.length} maintain, ${pushTeams.length} write, ${pullTeams.length} read.`,
          remediation: "No action needed.",
          reference: "https://docs.github.com/en/organizations/managing-user-access-to-your-organizations-repositories/managing-team-access-to-an-organization-repository",
        });
      }
    } catch (err: any) {
      if (err.status === 404 || err.status === 403) {
        results.push({
          checkId: "ACC-001",
          title: "Team permissions check not accessible",
          severity: "HIGH",
          status: "NOT_APPLICABLE",
          resource,
          category: "access",
          details: `Cannot access team information (HTTP ${err.status}). The repository may not be organization-owned, or the token lacks org:read scope.`,
          remediation: "Ensure the token has read:org scope and the repository belongs to an organization.",
          reference: "https://docs.github.com/en/organizations/managing-user-access-to-your-organizations-repositories/managing-team-access-to-an-organization-repository",
        });
      } else {
        results.push({
          checkId: "ACC-001",
          title: "Team permissions check failed",
          severity: "HIGH",
          status: "ERROR",
          resource,
          category: "access",
          details: `Failed to check team permissions: ${err.message}`,
          remediation: "Ensure the token has read:org scope.",
        });
      }
    }
  } else {
    // Org-level check: list all teams and permission summary
    try {
      const { data: teams } = await client.rest().teams.list({
        org,
        per_page: 100,
      });

      if (teams.length === 0) {
        results.push({
          checkId: "ACC-001",
          title: "No teams in organization",
          severity: "HIGH",
          status: "PASS",
          resource,
          category: "access",
          details: `Organization '${org}' has no teams configured.`,
          remediation: "No action needed. Consider creating teams for structured access management.",
          reference: "https://docs.github.com/en/organizations/organizing-members-into-teams/about-teams",
        });
        return results;
      }

      const secretTeams = teams.filter((t) => t.privacy === "secret");
      const teamSummary = teams
        .slice(0, 10)
        .map((t) => `- ${t.name} (slug: ${t.slug}, privacy: ${t.privacy ?? "visible"}, members: ${(t as any).members_count ?? "unknown"})`)
        .join("\n");

      results.push({
        checkId: "ACC-001",
        title: "Organization team inventory",
        severity: "HIGH",
        status: "PASS",
        resource,
        category: "access",
        details: `Organization '${org}' has ${teams.length} team(s). ${secretTeams.length} are secret teams.\n\nTeams (first 10):\n${teamSummary}${teams.length > 10 ? `\n... and ${teams.length - 10} more` : ""}\n\nUse the repo-scoped check (with owner + repo) to identify teams with admin access on specific repositories.`,
        remediation: "Review team structure periodically. For per-repo admin access checks, run this check with a specific repository.",
        reference: "https://docs.github.com/en/organizations/organizing-members-into-teams/about-teams",
      });
    } catch (err: any) {
      if (err.status === 404 || err.status === 403) {
        results.push({
          checkId: "ACC-001",
          title: "Organization teams not accessible",
          severity: "HIGH",
          status: "NOT_APPLICABLE",
          resource,
          category: "access",
          details: `Cannot access organization teams (HTTP ${err.status}). The token may lack read:org scope or the organization does not exist.`,
          remediation: "Ensure the token has read:org scope and the organization name is correct.",
          reference: "https://docs.github.com/en/organizations/organizing-members-into-teams/about-teams",
        });
      } else {
        results.push({
          checkId: "ACC-001",
          title: "Organization teams check failed",
          severity: "HIGH",
          status: "ERROR",
          resource,
          category: "access",
          details: `Failed to list organization teams: ${err.message}`,
          remediation: "Ensure the token has read:org scope.",
        });
      }
    }
  }

  return results;
}
