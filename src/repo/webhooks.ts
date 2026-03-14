import type { CheckResult } from "../types/index.js";
import type { GitHubClientFactory } from "../github/client.js";

/**
 * REPO-011: Insecure webhook configuration check.
 * Verifies that webhooks use HTTPS URLs and have SSL verification enabled.
 */
export async function checkRepoWebhooks(
  client: GitHubClientFactory,
  args: Record<string, unknown>,
): Promise<CheckResult[]> {
  const owner = args.owner as string;
  const repo = args.repo as string;
  const results: CheckResult[] = [];
  const resource = `${owner}/${repo}`;

  try {
    const { data: hooks } = await client.rest().repos.listWebhooks({
      owner,
      repo,
      per_page: 100,
    });

    if (hooks.length === 0) {
      results.push({
        checkId: "REPO-011",
        title: "No webhooks configured",
        severity: "MEDIUM",
        status: "PASS",
        resource,
        category: "repo",
        details: "No webhooks are configured on this repository.",
        remediation: "No action needed.",
        reference: "https://docs.github.com/en/webhooks/using-webhooks/best-practices-for-using-webhooks",
      });
      return results;
    }

    const insecureHooks: string[] = [];
    const sslDisabledHooks: string[] = [];

    for (const hook of hooks) {
      const config = hook.config as any;
      const url = config?.url ?? "";
      const hookId = `webhook #${hook.id}`;

      if (url.startsWith("http://")) {
        insecureHooks.push(`${hookId}: ${url}`);
      }

      if (config?.insecure_ssl === "1") {
        sslDisabledHooks.push(`${hookId}: ${url}`);
      }
    }

    const issues: string[] = [];

    if (insecureHooks.length > 0) {
      issues.push(`${insecureHooks.length} webhook(s) using insecure HTTP:\n  ${insecureHooks.join("\n  ")}`);
    }

    if (sslDisabledHooks.length > 0) {
      issues.push(`${sslDisabledHooks.length} webhook(s) with SSL verification disabled:\n  ${sslDisabledHooks.join("\n  ")}`);
    }

    if (issues.length > 0) {
      results.push({
        checkId: "REPO-011",
        title: "Insecure webhook configuration detected",
        severity: "MEDIUM",
        status: "FAIL",
        resource,
        category: "repo",
        details: `Found ${hooks.length} webhook(s) with security issues:\n\n${issues.join("\n\n")}`,
        remediation: "Update webhook URLs to use HTTPS and enable SSL verification. Edit each webhook in Settings > Webhooks. Ensure 'SSL verification' is enabled and the payload URL uses https://.",
        reference: "https://docs.github.com/en/webhooks/using-webhooks/best-practices-for-using-webhooks",
      });
    } else {
      results.push({
        checkId: "REPO-011",
        title: "All webhooks use secure configuration",
        severity: "MEDIUM",
        status: "PASS",
        resource,
        category: "repo",
        details: `All ${hooks.length} webhook(s) use HTTPS URLs and have SSL verification enabled.`,
        remediation: "No action needed.",
        reference: "https://docs.github.com/en/webhooks/using-webhooks/best-practices-for-using-webhooks",
      });
    }
  } catch (err: any) {
    if (err.status === 404 || err.status === 403) {
      results.push({
        checkId: "REPO-011",
        title: "Webhook check not accessible",
        severity: "MEDIUM",
        status: "NOT_APPLICABLE",
        resource,
        category: "repo",
        details: `Cannot access webhooks (HTTP ${err.status}). The token may lack admin:repo_hook scope.`,
        remediation: "Ensure the token has admin:repo_hook scope to list webhooks.",
        reference: "https://docs.github.com/en/webhooks/using-webhooks/best-practices-for-using-webhooks",
      });
    } else {
      results.push({
        checkId: "REPO-011",
        title: "Webhook check failed",
        severity: "MEDIUM",
        status: "ERROR",
        resource,
        category: "repo",
        details: `Failed to check webhooks: ${err.message}`,
        remediation: "Ensure the token has admin:repo_hook scope.",
      });
    }
  }

  return results;
}
