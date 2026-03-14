import type { CheckResult } from "../types/index.js";
import type { GitHubClientFactory } from "../github/client.js";

/**
 * REPO-004: Code scanning enabled check.
 * REPO-005: Open code scanning alerts check.
 * Verifies that code scanning (CodeQL or third-party) is configured and checks for open alerts.
 */
export async function checkCodeScanning(
  client: GitHubClientFactory,
  args: Record<string, unknown>,
): Promise<CheckResult[]> {
  const owner = args.owner as string;
  const repo = args.repo as string;
  const results: CheckResult[] = [];
  const resource = `${owner}/${repo}`;

  // REPO-004: Check if code scanning is configured
  let codeScanningEnabled = false;
  try {
    const { data: analyses } = await client.rest().codeScanning.listRecentAnalyses({
      owner,
      repo,
      per_page: 1,
    });
    codeScanningEnabled = analyses.length > 0;

    if (codeScanningEnabled) {
      const latestAnalysis = analyses[0];
      results.push({
        checkId: "REPO-004",
        title: "Code scanning enabled",
        severity: "MEDIUM",
        status: "PASS",
        resource,
        category: "repo",
        details: `Code scanning is configured. Latest analysis tool: '${latestAnalysis.tool?.name ?? "unknown"}', created at ${latestAnalysis.created_at}.`,
        remediation: "No action needed.",
        reference: "https://docs.github.com/en/code-security/code-scanning/automatically-scanning-your-code-for-vulnerabilities-and-errors",
      });
    } else {
      results.push({
        checkId: "REPO-004",
        title: "Code scanning not enabled",
        severity: "MEDIUM",
        status: "FAIL",
        resource,
        category: "repo",
        details: "No code scanning analyses found. Code scanning (e.g., CodeQL) is not configured for this repository.",
        remediation: "Enable code scanning: Settings > Code security and analysis > Code scanning > Set up. Consider using the default CodeQL workflow.",
        reference: "https://docs.github.com/en/code-security/code-scanning/automatically-scanning-your-code-for-vulnerabilities-and-errors",
      });
    }
  } catch (err: any) {
    if (err.status === 404 || err.status === 403) {
      results.push({
        checkId: "REPO-004",
        title: "Code scanning not enabled",
        severity: "MEDIUM",
        status: "FAIL",
        resource,
        category: "repo",
        details: "Code scanning is not configured for this repository (API returned 404). No analysis results are available.",
        remediation: "Enable code scanning: Settings > Code security and analysis > Code scanning > Set up. Consider using the default CodeQL workflow.",
        reference: "https://docs.github.com/en/code-security/code-scanning/automatically-scanning-your-code-for-vulnerabilities-and-errors",
      });
    } else {
      results.push({
        checkId: "REPO-004",
        title: "Code scanning check failed",
        severity: "MEDIUM",
        status: "ERROR",
        resource,
        category: "repo",
        details: `Failed to check code scanning: ${err.message}`,
        remediation: "Ensure the token has security_events scope.",
      });
    }
  }

  // REPO-005: Check for open code scanning alerts
  if (codeScanningEnabled) {
    try {
      const { data: alerts } = await client.rest().codeScanning.listAlertsForRepo({
        owner,
        repo,
        state: "open",
        per_page: 100,
      });

      const criticalAlerts = alerts.filter(
        (a: any) => a.rule?.security_severity_level === "critical" || a.rule?.severity === "error",
      );
      const highAlerts = alerts.filter(
        (a: any) => a.rule?.security_severity_level === "high",
      );

      if (criticalAlerts.length > 0) {
        const alertSummary = criticalAlerts
          .slice(0, 5)
          .map((a: any) => `- ${a.rule?.id ?? "unknown"}: ${a.rule?.description ?? a.most_recent_instance?.message?.text ?? "No description"}`)
          .join("\n");

        results.push({
          checkId: "REPO-005",
          title: "Critical/error code scanning alerts found",
          severity: "HIGH",
          status: "FAIL",
          resource,
          category: "repo",
          details: `Found ${criticalAlerts.length} critical/error severity open alert(s) and ${highAlerts.length} high severity alert(s). Total open alerts: ${alerts.length}.\n\nTop critical alerts:\n${alertSummary}`,
          remediation: "Review and remediate open code scanning alerts: Security tab > Code scanning alerts. Prioritize critical and error severity findings.",
          reference: "https://docs.github.com/en/code-security/code-scanning/managing-code-scanning-alerts/managing-code-scanning-alerts-for-your-repository",
        });
      } else if (alerts.length > 0) {
        results.push({
          checkId: "REPO-005",
          title: "Open code scanning alerts found (non-critical)",
          severity: "HIGH",
          status: "PASS",
          resource,
          category: "repo",
          details: `Found ${alerts.length} open code scanning alert(s) but none are critical/error severity. ${highAlerts.length} high severity alert(s).`,
          remediation: "Review open code scanning alerts periodically. Address high severity findings when possible.",
          reference: "https://docs.github.com/en/code-security/code-scanning/managing-code-scanning-alerts/managing-code-scanning-alerts-for-your-repository",
        });
      } else {
        results.push({
          checkId: "REPO-005",
          title: "No open code scanning alerts",
          severity: "HIGH",
          status: "PASS",
          resource,
          category: "repo",
          details: "No open code scanning alerts found. All detected issues have been resolved or dismissed.",
          remediation: "No action needed.",
          reference: "https://docs.github.com/en/code-security/code-scanning/managing-code-scanning-alerts/managing-code-scanning-alerts-for-your-repository",
        });
      }
    } catch (err: any) {
      results.push({
        checkId: "REPO-005",
        title: "Code scanning alerts check failed",
        severity: "HIGH",
        status: "ERROR",
        resource,
        category: "repo",
        details: `Failed to list code scanning alerts: ${err.message}`,
        remediation: "Ensure the token has security_events scope.",
      });
    }
  } else {
    results.push({
      checkId: "REPO-005",
      title: "Code scanning alerts check skipped",
      severity: "HIGH",
      status: "NOT_APPLICABLE",
      resource,
      category: "repo",
      details: "Code scanning is not enabled, so alert checks are not applicable.",
      remediation: "Enable code scanning first (see REPO-004).",
      reference: "https://docs.github.com/en/code-security/code-scanning/managing-code-scanning-alerts/managing-code-scanning-alerts-for-your-repository",
    });
  }

  return results;
}
