import type { CheckResult } from "../types/index.js";
import type { GitHubClientFactory } from "../github/client.js";

const STALE_THRESHOLD_DAYS = 90;

/**
 * SUP-004: Critical known vulnerabilities in dependencies.
 * SUP-005: Stale unfixed vulnerabilities (open > 90 days).
 *
 * Checks Dependabot alerts for open critical vulnerabilities and for alerts that have
 * remained open for an extended period, indicating a lack of remediation process.
 */
export async function checkVulnerabilities(
  client: GitHubClientFactory,
  args: Record<string, unknown>,
): Promise<CheckResult[]> {
  const owner = args.owner as string;
  const repo = args.repo as string;
  const results: CheckResult[] = [];
  const resource = `${owner}/${repo}`;

  // SUP-004: Critical vulnerabilities
  try {
    const { data: criticalAlerts } = await client.rest().dependabot.listAlertsForRepo({
      owner,
      repo,
      state: "open",
      severity: "critical",
      per_page: 100,
    });

    if (criticalAlerts.length > 0) {
      const alertSummaries = criticalAlerts.slice(0, 10).map((alert: any) => {
        const pkg = alert.security_advisory?.summary ?? alert.dependency?.package?.name ?? "unknown";
        const cve = alert.security_advisory?.cve_id ?? "N/A";
        return `#${alert.number}: ${pkg} (${cve})`;
      });

      const moreText = criticalAlerts.length > 10
        ? `\n... and ${criticalAlerts.length - 10} more critical alerts`
        : "";

      results.push({
        checkId: "SUP-004",
        title: "Critical known vulnerabilities in dependencies",
        severity: "CRITICAL",
        status: "FAIL",
        resource,
        category: "supply-chain",
        details:
          `Repository '${resource}' has ${criticalAlerts.length} open critical Dependabot alert(s):\n` +
          `- ${alertSummaries.join("\n- ")}${moreText}`,
        remediation:
          "Address critical vulnerabilities immediately:\n" +
          "1. Review each alert at https://github.com/" + resource + "/security/dependabot\n" +
          "2. Update affected dependencies to patched versions.\n" +
          "3. If no patch is available, consider alternative packages or apply workarounds.\n" +
          "4. Enable Dependabot security updates to get automatic fix PRs.",
        reference:
          "https://docs.github.com/en/code-security/dependabot/dependabot-alerts/viewing-and-updating-dependabot-alerts",
      });
    } else {
      results.push({
        checkId: "SUP-004",
        title: "No critical vulnerabilities in dependencies",
        severity: "CRITICAL",
        status: "PASS",
        resource,
        category: "supply-chain",
        details: `Repository '${resource}' has no open critical Dependabot alerts.`,
        remediation: "No action needed.",
        reference:
          "https://docs.github.com/en/code-security/dependabot/dependabot-alerts/viewing-and-updating-dependabot-alerts",
      });
    }
  } catch (err: any) {
    if (err.status === 404 || err.status === 403) {
      results.push({
        checkId: "SUP-004",
        title: "Cannot access Dependabot alerts",
        severity: "CRITICAL",
        status: "ERROR",
        resource,
        category: "supply-chain",
        details:
          `Cannot access Dependabot alerts for '${resource}'. ` +
          "Dependabot alerts may not be enabled, or the token lacks sufficient permissions.",
        remediation:
          "Enable Dependabot alerts: Settings > Code security and analysis > Dependabot alerts > Enable.\n" +
          "Ensure the token has the 'security_events' scope or is a repo admin.",
      });
    } else {
      const message = err instanceof Error ? err.message : String(err);
      results.push({
        checkId: "SUP-004",
        title: "Critical vulnerability check failed",
        severity: "CRITICAL",
        status: "ERROR",
        resource,
        category: "supply-chain",
        details: `Failed to check critical vulnerabilities for '${resource}': ${message}`,
        remediation: "Ensure the token has repo and security_events scopes.",
      });
    }
  }

  // SUP-005: Stale unfixed vulnerabilities (open > 90 days)
  try {
    const { data: allAlerts } = await client.rest().dependabot.listAlertsForRepo({
      owner,
      repo,
      state: "open",
      per_page: 100,
    });

    const now = Date.now();
    const thresholdMs = STALE_THRESHOLD_DAYS * 24 * 60 * 60 * 1000;
    const staleAlerts = allAlerts.filter((alert: any) => {
      const createdAt = new Date(alert.created_at).getTime();
      return now - createdAt > thresholdMs;
    });

    if (staleAlerts.length > 0) {
      const staleSummaries = staleAlerts.slice(0, 10).map((alert: any) => {
        const pkg = alert.dependency?.package?.name ?? "unknown";
        const severity = alert.security_advisory?.severity ?? "unknown";
        const createdAt = alert.created_at?.slice(0, 10) ?? "unknown";
        const daysOpen = Math.floor((now - new Date(alert.created_at).getTime()) / (24 * 60 * 60 * 1000));
        return `#${alert.number}: ${pkg} (${severity}, open ${daysOpen} days since ${createdAt})`;
      });

      const moreText = staleAlerts.length > 10
        ? `\n... and ${staleAlerts.length - 10} more stale alerts`
        : "";

      results.push({
        checkId: "SUP-005",
        title: "Stale unfixed vulnerabilities",
        severity: "HIGH",
        status: "FAIL",
        resource,
        category: "supply-chain",
        details:
          `Repository '${resource}' has ${staleAlerts.length} Dependabot alert(s) open for more than ${STALE_THRESHOLD_DAYS} days:\n` +
          `- ${staleSummaries.join("\n- ")}${moreText}`,
        remediation:
          "Establish a vulnerability remediation SLA:\n" +
          `1. Critical/High: Fix within 7-14 days.\n` +
          `2. Medium: Fix within 30 days.\n` +
          `3. Low: Fix within 90 days.\n` +
          "4. If a fix is not available, dismiss the alert with a reason (e.g., 'tolerable_risk', 'no_bandwidth').\n" +
          "5. Enable Dependabot security updates for automatic fix PRs.",
        reference:
          "https://docs.github.com/en/code-security/dependabot/dependabot-alerts/viewing-and-updating-dependabot-alerts",
      });
    } else {
      results.push({
        checkId: "SUP-005",
        title: "No stale unfixed vulnerabilities",
        severity: "HIGH",
        status: "PASS",
        resource,
        category: "supply-chain",
        details:
          `Repository '${resource}' has no Dependabot alerts open for more than ${STALE_THRESHOLD_DAYS} days.`,
        remediation: "No action needed.",
        reference:
          "https://docs.github.com/en/code-security/dependabot/dependabot-alerts/viewing-and-updating-dependabot-alerts",
      });
    }
  } catch (err: any) {
    // Only add error if we didn't already report an access error for SUP-004
    if (err.status !== 404 && err.status !== 403) {
      const message = err instanceof Error ? err.message : String(err);
      results.push({
        checkId: "SUP-005",
        title: "Stale vulnerability check failed",
        severity: "HIGH",
        status: "ERROR",
        resource,
        category: "supply-chain",
        details: `Failed to check stale vulnerabilities for '${resource}': ${message}`,
        remediation: "Ensure the token has repo and security_events scopes.",
      });
    }
  }

  return results;
}
