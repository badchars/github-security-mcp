import type { CheckResult } from "../types/index.js";
import type { GitHubClientFactory } from "../github/client.js";

const SENSITIVE_ENV_NAMES = ["production", "prod", "staging", "stage", "live"];

/**
 * ACT-006: Missing environment protections.
 *
 * Deployment environments should have protection rules (required reviewers, wait timers,
 * branch restrictions) to prevent unauthorized deployments. Unprotected production/staging
 * environments allow any workflow to deploy without human approval.
 */
export async function checkEnvironments(
  client: GitHubClientFactory,
  args: Record<string, unknown>,
): Promise<CheckResult[]> {
  const owner = args.owner as string;
  const repo = args.repo as string;
  const results: CheckResult[] = [];
  const resource = `${owner}/${repo}`;

  try {
    const { data } = await client.rest().repos.getAllEnvironments({
      owner,
      repo,
      per_page: 100,
    }) as { data: { total_count: number; environments: any[] } };

    if (!data.environments || data.environments.length === 0) {
      results.push({
        checkId: "ACT-006",
        title: "No deployment environments configured",
        severity: "MEDIUM",
        status: "NOT_APPLICABLE",
        resource,
        category: "actions",
        details: `Repository '${resource}' has no deployment environments configured.`,
        remediation: "No action needed — no environments to audit.",
      });
      return results;
    }

    for (const env of data.environments) {
      const envName = env.name as string;
      const envLower = envName.toLowerCase();
      const isSensitive = SENSITIVE_ENV_NAMES.some(
        (name) => envLower === name || envLower.includes(name),
      );

      if (!isSensitive) continue;

      const protectionRules: any[] = env.protection_rules ?? [];
      const issues: string[] = [];

      // Check for required reviewers
      const hasReviewers = protectionRules.some(
        (rule: any) => rule.type === "required_reviewers",
      );
      if (!hasReviewers) {
        issues.push("No required reviewers configured");
      }

      // Check for wait timer
      const hasWaitTimer = protectionRules.some(
        (rule: any) => rule.type === "wait_timer" && (rule.wait_timer ?? 0) > 0,
      );
      if (!hasWaitTimer) {
        issues.push("No wait timer configured");
      }

      // Check for deployment branch policy
      const hasBranchPolicy = env.deployment_branch_policy !== null &&
        env.deployment_branch_policy !== undefined;
      if (!hasBranchPolicy) {
        issues.push("No deployment branch policy — any branch can deploy");
      }

      if (issues.length > 0) {
        results.push({
          checkId: "ACT-006",
          title: `Unprotected deployment environment: ${envName}`,
          severity: "MEDIUM",
          status: "FAIL",
          resource: `${resource}/environments/${envName}`,
          category: "actions",
          details:
            `Environment '${envName}' is a sensitive deployment target but lacks adequate protection:\n` +
            `- ${issues.join("\n- ")}`,
          remediation:
            `Go to Settings > Environments > ${envName} and configure:\n` +
            "1. Required reviewers — at least one person must approve before deployment.\n" +
            "2. Wait timer — add a delay (e.g., 5 minutes) to allow cancellation.\n" +
            "3. Deployment branches — restrict to 'main' or 'release/*' only.",
          reference:
            "https://docs.github.com/en/actions/managing-workflow-runs-and-deployments/managing-deployments/managing-environments-for-deployment",
        });
      } else {
        results.push({
          checkId: "ACT-006",
          title: `Environment '${envName}' is properly protected`,
          severity: "MEDIUM",
          status: "PASS",
          resource: `${resource}/environments/${envName}`,
          category: "actions",
          details:
            `Environment '${envName}' has required reviewers, wait timer, and deployment branch policy configured.`,
          remediation: "No action needed.",
          reference:
            "https://docs.github.com/en/actions/managing-workflow-runs-and-deployments/managing-deployments/managing-environments-for-deployment",
        });
      }
    }

    // If no sensitive environments were found, note it
    if (results.length === 0) {
      results.push({
        checkId: "ACT-006",
        title: "No sensitive deployment environments found",
        severity: "MEDIUM",
        status: "PASS",
        resource,
        category: "actions",
        details:
          `Repository '${resource}' has ${data.environments.length} environment(s), ` +
          `but none match sensitive names (production, prod, staging, etc.).`,
        remediation: "No action needed.",
      });
    }
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    results.push({
      checkId: "ACT-006",
      title: "Missing environment protections",
      severity: "MEDIUM",
      status: "ERROR",
      resource,
      category: "actions",
      details: `Failed to check environments for '${resource}': ${message}`,
      remediation: "Ensure the token has repo scope and the repository exists.",
    });
  }

  return results;
}
