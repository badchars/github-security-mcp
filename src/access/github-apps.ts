import type { CheckResult } from "../types/index.js";
import type { GitHubClientFactory } from "../github/client.js";

/**
 * ACC-003: Over-scoped GitHub App installations check.
 * Checks GitHub Apps installed on a repository for overly broad permissions.
 */
export async function checkAppPermissions(
  client: GitHubClientFactory,
  args: Record<string, unknown>,
): Promise<CheckResult[]> {
  const owner = args.owner as string;
  const repo = args.repo as string;
  const results: CheckResult[] = [];
  const resource = `${owner}/${repo}`;

  // High-risk permissions that warrant attention
  const highRiskPerms: Record<string, string> = {
    administration: "Can change repository settings, branch protection, and team access",
    contents: "Can read and write repository contents, commits, and branches",
    actions: "Can manage GitHub Actions workflows and secrets",
    environments: "Can manage deployment environments and secrets",
    secrets: "Can manage repository and organization secrets",
    workflows: "Can update GitHub Actions workflow files",
    members: "Can manage organization membership",
    organization_administration: "Can manage organization settings",
    organization_secrets: "Can manage organization-level secrets",
  };

  try {
    // Use the REST API to list installations for a specific repository
    const { data } = await client.rest().request(
      "GET /repos/{owner}/{repo}/installations",
      {
        owner,
        repo,
        per_page: 100,
      },
    );

    const installations = (data as any).installations ?? [];

    if (installations.length === 0) {
      results.push({
        checkId: "ACC-003",
        title: "No GitHub Apps installed",
        severity: "HIGH",
        status: "PASS",
        resource,
        category: "access",
        details: "No GitHub Apps are installed on this repository.",
        remediation: "No action needed.",
        reference: "https://docs.github.com/en/apps/using-github-apps/reviewing-and-modifying-installed-github-apps",
      });
      return results;
    }

    const overScopedApps: string[] = [];
    const appSummaries: string[] = [];

    for (const installation of installations) {
      const appName = installation.app_slug ?? installation.app_id ?? "unknown";
      const permissions = installation.permissions ?? {};
      const riskyPerms: string[] = [];

      for (const [perm, level] of Object.entries(permissions)) {
        if (level === "write" && highRiskPerms[perm]) {
          riskyPerms.push(`${perm}: write — ${highRiskPerms[perm]}`);
        }
      }

      const permCount = Object.keys(permissions).length;
      const writePerms = Object.entries(permissions).filter(([_, v]) => v === "write").length;

      if (riskyPerms.length > 0) {
        overScopedApps.push(
          `${appName} (${writePerms} write / ${permCount} total permissions):\n    ${riskyPerms.join("\n    ")}`,
        );
      }

      appSummaries.push(
        `- ${appName}: ${writePerms} write, ${permCount - writePerms} read permissions${riskyPerms.length > 0 ? " [OVER-SCOPED]" : ""}`,
      );
    }

    if (overScopedApps.length > 0) {
      results.push({
        checkId: "ACC-003",
        title: "Over-scoped GitHub App permissions detected",
        severity: "HIGH",
        status: "FAIL",
        resource,
        category: "access",
        details: `Found ${overScopedApps.length} GitHub App(s) with high-risk write permissions (out of ${installations.length} total).\n\nOver-scoped apps:\n${overScopedApps.join("\n\n")}\n\nAll installed apps:\n${appSummaries.join("\n")}`,
        remediation: "Review GitHub App permissions in Settings > GitHub Apps > Configure. Reduce write permissions where read-only is sufficient. Consider whether each app truly needs administration, contents:write, or secrets access.",
        reference: "https://docs.github.com/en/apps/using-github-apps/reviewing-and-modifying-installed-github-apps",
      });
    } else {
      results.push({
        checkId: "ACC-003",
        title: "GitHub App permissions are reasonable",
        severity: "HIGH",
        status: "PASS",
        resource,
        category: "access",
        details: `${installations.length} GitHub App(s) installed. No apps have high-risk write permissions.\n\nInstalled apps:\n${appSummaries.join("\n")}`,
        remediation: "No action needed. Periodically review installed apps.",
        reference: "https://docs.github.com/en/apps/using-github-apps/reviewing-and-modifying-installed-github-apps",
      });
    }
  } catch (err: any) {
    if (err.status === 404 || err.status === 403) {
      // Fallback: try listing installations for the authenticated user
      try {
        const { data } = await client.rest().apps.listInstallationsForAuthenticatedUser({
          per_page: 100,
        });

        const installations = data.installations ?? [];
        const repoInstallations = installations.filter((inst: any) => {
          // Filter to installations that may have access to this repo
          if (inst.repository_selection === "all") return true;
          // Cannot determine specific repos without additional API calls
          return false;
        });

        if (installations.length === 0) {
          results.push({
            checkId: "ACC-003",
            title: "No GitHub App installations found",
            severity: "HIGH",
            status: "PASS",
            resource,
            category: "access",
            details: "No GitHub App installations found for the authenticated user.",
            remediation: "No action needed.",
            reference: "https://docs.github.com/en/apps/using-github-apps/reviewing-and-modifying-installed-github-apps",
          });
        } else {
          const allAccessApps = installations.filter(
            (i: any) => i.repository_selection === "all",
          );

          results.push({
            checkId: "ACC-003",
            title: "GitHub App installations overview",
            severity: "HIGH",
            status: allAccessApps.length > 0 ? "FAIL" : "PASS",
            resource,
            category: "access",
            details: `Found ${installations.length} GitHub App installation(s) for the authenticated user. ${allAccessApps.length} have access to ALL repositories.\n\nNote: Could not query repo-specific installations (HTTP ${err.status}). Showing user-level installations instead.`,
            remediation: allAccessApps.length > 0
              ? "Review apps with access to ALL repositories. Restrict to specific repositories where possible. Settings > Applications > Installed GitHub Apps."
              : "No action needed.",
            reference: "https://docs.github.com/en/apps/using-github-apps/reviewing-and-modifying-installed-github-apps",
          });
        }
      } catch (fallbackErr: any) {
        results.push({
          checkId: "ACC-003",
          title: "GitHub App permissions check not accessible",
          severity: "HIGH",
          status: "NOT_APPLICABLE",
          resource,
          category: "access",
          details: `Cannot access GitHub App installation information. Primary API returned HTTP ${err.status}, fallback also failed: ${fallbackErr.message}. The token may lack the required scope.`,
          remediation: "Ensure the token has read:org scope. For fine-grained tokens, the 'organization administration: read' permission is required.",
          reference: "https://docs.github.com/en/apps/using-github-apps/reviewing-and-modifying-installed-github-apps",
        });
      }
    } else {
      results.push({
        checkId: "ACC-003",
        title: "GitHub App permissions check failed",
        severity: "HIGH",
        status: "ERROR",
        resource,
        category: "access",
        details: `Failed to check GitHub App permissions: ${err.message}`,
        remediation: "Ensure the token has the required scope to list installations.",
      });
    }
  }

  return results;
}
