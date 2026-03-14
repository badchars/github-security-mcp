import type { CheckResult } from "../types/index.js";
import type { GitHubClientFactory } from "../github/client.js";

/**
 * REPO-006: Dependabot security updates enabled check.
 * REPO-007: Critical Dependabot alerts open check.
 * Verifies that Dependabot is active and checks for unresolved critical alerts.
 */
export async function checkDependabot(
  client: GitHubClientFactory,
  args: Record<string, unknown>,
): Promise<CheckResult[]> {
  const owner = args.owner as string;
  const repo = args.repo as string;
  const results: CheckResult[] = [];
  const resource = `${owner}/${repo}`;

  // REPO-006: Check if Dependabot security updates are enabled
  try {
    const { data: repoData } = await client.rest().repos.get({ owner, repo });
    const securityAnalysis = (repoData as any).security_and_analysis;

    if (!securityAnalysis?.dependabot_security_updates) {
      results.push({
        checkId: "REPO-006",
        title: "Dependabot security updates status unavailable",
        severity: "MEDIUM",
        status: "NOT_APPLICABLE",
        resource,
        category: "repo",
        details: "Dependabot security updates information is not available. This may indicate the feature is not supported on the current plan or repository type.",
        remediation: "Enable Dependabot security updates: Settings > Code security and analysis > Dependabot security updates > Enable.",
        reference: "https://docs.github.com/en/code-security/dependabot/dependabot-security-updates/configuring-dependabot-security-updates",
      });
    } else if (securityAnalysis.dependabot_security_updates.status !== "enabled") {
      results.push({
        checkId: "REPO-006",
        title: "Dependabot security updates not enabled",
        severity: "MEDIUM",
        status: "FAIL",
        resource,
        category: "repo",
        details: `Dependabot security updates status is '${securityAnalysis.dependabot_security_updates.status}'. Vulnerable dependencies will not be automatically patched.`,
        remediation: "Enable Dependabot security updates: Settings > Code security and analysis > Dependabot security updates > Enable.",
        reference: "https://docs.github.com/en/code-security/dependabot/dependabot-security-updates/configuring-dependabot-security-updates",
      });
    } else {
      results.push({
        checkId: "REPO-006",
        title: "Dependabot security updates enabled",
        severity: "MEDIUM",
        status: "PASS",
        resource,
        category: "repo",
        details: "Dependabot security updates are enabled. Vulnerable dependencies will automatically receive pull requests with patches.",
        remediation: "No action needed.",
        reference: "https://docs.github.com/en/code-security/dependabot/dependabot-security-updates/configuring-dependabot-security-updates",
      });
    }
  } catch (err: any) {
    results.push({
      checkId: "REPO-006",
      title: "Dependabot security updates check failed",
      severity: "MEDIUM",
      status: "ERROR",
      resource,
      category: "repo",
      details: `Failed to check Dependabot security updates: ${err.message}`,
      remediation: "Ensure the token has repo scope and the repository exists.",
    });
  }

  // REPO-007: Check for critical Dependabot alerts
  try {
    const { data: alerts } = await client.rest().dependabot.listAlertsForRepo({
      owner,
      repo,
      state: "open",
      severity: "critical",
      per_page: 100,
    });

    if (alerts.length > 0) {
      const alertSummary = alerts
        .slice(0, 5)
        .map((a: any) => {
          const advisory = a.security_advisory;
          const pkg = a.dependency?.package;
          return `- ${pkg?.ecosystem ?? ""}/${pkg?.name ?? "unknown"}: ${advisory?.summary ?? "No summary"} (GHSA: ${advisory?.ghsa_id ?? "N/A"})`;
        })
        .join("\n");

      results.push({
        checkId: "REPO-007",
        title: "Critical Dependabot alerts open",
        severity: "CRITICAL",
        status: "FAIL",
        resource,
        category: "repo",
        details: `Found ${alerts.length} open critical Dependabot alert(s). These are known vulnerabilities in dependencies that may be actively exploited.\n\nTop alerts:\n${alertSummary}${alerts.length > 5 ? `\n... and ${alerts.length - 5} more` : ""}`,
        remediation: "Review and remediate critical Dependabot alerts immediately: Security tab > Dependabot alerts. Update affected dependencies or apply Dependabot-suggested fixes.",
        reference: "https://docs.github.com/en/code-security/dependabot/dependabot-alerts/viewing-and-updating-dependabot-alerts",
      });
    } else {
      results.push({
        checkId: "REPO-007",
        title: "No critical Dependabot alerts",
        severity: "CRITICAL",
        status: "PASS",
        resource,
        category: "repo",
        details: "No open critical Dependabot alerts found.",
        remediation: "No action needed.",
        reference: "https://docs.github.com/en/code-security/dependabot/dependabot-alerts/viewing-and-updating-dependabot-alerts",
      });
    }
  } catch (err: any) {
    if (err.status === 403 || err.status === 404) {
      results.push({
        checkId: "REPO-007",
        title: "Dependabot alerts not accessible",
        severity: "CRITICAL",
        status: "NOT_APPLICABLE",
        resource,
        category: "repo",
        details: `Cannot access Dependabot alerts (HTTP ${err.status}). Dependabot alerts may not be enabled, or the token lacks the required scope.`,
        remediation: "Enable Dependabot alerts: Settings > Code security and analysis > Dependabot alerts > Enable. Ensure the token has the 'security_events' or 'repo' scope.",
        reference: "https://docs.github.com/en/code-security/dependabot/dependabot-alerts/viewing-and-updating-dependabot-alerts",
      });
    } else {
      results.push({
        checkId: "REPO-007",
        title: "Dependabot alerts check failed",
        severity: "CRITICAL",
        status: "ERROR",
        resource,
        category: "repo",
        details: `Failed to check Dependabot alerts: ${err.message}`,
        remediation: "Ensure the token has repo or security_events scope.",
      });
    }
  }

  return results;
}
