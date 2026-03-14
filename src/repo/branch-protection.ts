import type { CheckResult } from "../types/index.js";
import type { GitHubClientFactory } from "../github/client.js";

/**
 * REPO-001: Check branch protection rules on the default branch.
 * Verifies that required reviews, admin enforcement, and status checks are configured.
 */
export async function checkBranchProtection(
  client: GitHubClientFactory,
  args: Record<string, unknown>,
): Promise<CheckResult[]> {
  const owner = args.owner as string;
  const repo = args.repo as string;
  const results: CheckResult[] = [];
  const resource = `${owner}/${repo}`;

  try {
    // Get default branch name
    const { data: repoData } = await client.rest().repos.get({ owner, repo });
    const defaultBranch = repoData.default_branch;

    let protection: any;
    try {
      const { data } = await client.rest().repos.getBranchProtection({
        owner,
        repo,
        branch: defaultBranch,
      });
      protection = data;
    } catch (err: any) {
      if (err.status === 404) {
        results.push({
          checkId: "REPO-001",
          title: "No branch protection on default branch",
          severity: "CRITICAL",
          status: "FAIL",
          resource,
          category: "repo",
          details: `Default branch '${defaultBranch}' has no branch protection rules configured. Anyone with write access can push directly.`,
          remediation: `Enable branch protection on '${defaultBranch}': Settings > Branches > Add rule for '${defaultBranch}'. Require pull request reviews, status checks, and enforce for admins.`,
          reference: "https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-a-branch-protection-rule",
        });
        return results;
      }
      throw err;
    }

    // Check individual protection components
    const issues: string[] = [];

    const reviews = protection.required_pull_request_reviews;
    if (!reviews) {
      issues.push("Required pull request reviews are not configured");
    } else if ((reviews.required_approving_review_count ?? 0) < 1) {
      issues.push(`Required approving review count is ${reviews.required_approving_review_count ?? 0} (should be >= 1)`);
    }

    if (!protection.enforce_admins?.enabled) {
      issues.push("Branch protection is not enforced for administrators");
    }

    if (!protection.required_status_checks) {
      issues.push("Required status checks are not configured");
    }

    if (issues.length > 0) {
      results.push({
        checkId: "REPO-001",
        title: "Weak branch protection on default branch",
        severity: "CRITICAL",
        status: "FAIL",
        resource,
        category: "repo",
        details: `Default branch '${defaultBranch}' has branch protection but with gaps:\n- ${issues.join("\n- ")}`,
        remediation: `Strengthen branch protection on '${defaultBranch}': require at least 1 approving review, enforce for admins, and configure required status checks.`,
        reference: "https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-a-branch-protection-rule",
      });
    } else {
      results.push({
        checkId: "REPO-001",
        title: "Branch protection properly configured",
        severity: "CRITICAL",
        status: "PASS",
        resource,
        category: "repo",
        details: `Default branch '${defaultBranch}' has branch protection with required reviews (>= 1 approver), admin enforcement, and required status checks.`,
        remediation: "No action needed.",
        reference: "https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-a-branch-protection-rule",
      });
    }
  } catch (err: any) {
    results.push({
      checkId: "REPO-001",
      title: "Branch protection check failed",
      severity: "CRITICAL",
      status: "ERROR",
      resource,
      category: "repo",
      details: `Failed to check branch protection: ${err.message}`,
      remediation: "Ensure the token has repo scope and the repository exists.",
    });
  }

  return results;
}
