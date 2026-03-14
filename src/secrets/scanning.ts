import type { CheckResult } from "../types/index.js";
import type { GitHubClientFactory } from "../github/client.js";

/**
 * SEC-001: Secret scanning enabled on repository
 * SEC-002: Unresolved secret scanning alerts
 */
export async function checkSecretScanning(
  client: GitHubClientFactory,
  args: Record<string, unknown>,
): Promise<CheckResult[]> {
  const owner = args.owner as string;
  const repo = args.repo as string;
  const resource = `${owner}/${repo}`;
  const results: CheckResult[] = [];

  // SEC-001: Secret scanning coverage
  try {
    const { data: repoData } = await client
      .rest()
      .repos.get({ owner, repo });

    const securityAnalysis = (repoData as any).security_and_analysis;
    const secretScanning = securityAnalysis?.secret_scanning;
    const status = secretScanning?.status;

    results.push({
      checkId: "SEC-001",
      title: "Secret scanning not enabled",
      severity: "HIGH",
      status: status === "enabled" ? "PASS" : "FAIL",
      resource,
      category: "secrets",
      details:
        status === "enabled"
          ? `Repository '${resource}' has secret scanning enabled.`
          : `Repository '${resource}' does not have secret scanning enabled (status: ${status ?? "unknown"}). Leaked secrets in commits will not be detected automatically.`,
      remediation:
        "Enable secret scanning in Repository Settings > Code security and analysis > Secret scanning.",
      reference:
        "https://docs.github.com/en/code-security/secret-scanning/introduction/about-secret-scanning",
    });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    results.push({
      checkId: "SEC-001",
      title: "Secret scanning not enabled",
      severity: "HIGH",
      status: "ERROR",
      resource,
      category: "secrets",
      details: `Failed to check secret scanning status for '${resource}': ${message}`,
      remediation:
        "Verify the token has repo scope and the repository exists.",
    });
  }

  // SEC-002: Unresolved secret scanning alerts
  try {
    const { data: alerts } = await client
      .rest()
      .secretScanning.listAlertsForRepo({
        owner,
        repo,
        state: "open",
        per_page: 100,
      });

    const count = alerts.length;
    const secretTypes = [
      ...new Set(alerts.map((a: any) => a.secret_type_display_name ?? a.secret_type ?? "unknown")),
    ];

    results.push({
      checkId: "SEC-002",
      title: "Unresolved secret scanning alerts",
      severity: "CRITICAL",
      status: count > 0 ? "FAIL" : "PASS",
      resource,
      category: "secrets",
      details:
        count > 0
          ? `Repository '${resource}' has ${count} open secret scanning alert(s). Secret types found: ${secretTypes.join(", ")}. These are actively exposed secrets that require immediate remediation.`
          : `Repository '${resource}' has no open secret scanning alerts.`,
      remediation:
        "Rotate all exposed secrets immediately. Review each alert in the Security tab > Secret scanning alerts. Revoke compromised credentials and update them in your secret management system.",
      reference:
        "https://docs.github.com/en/code-security/secret-scanning/managing-alerts-from-secret-scanning/managing-alerts-from-secret-scanning",
    });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    // Secret scanning alerts API returns 404 if feature not enabled
    const isNotEnabled =
      message.includes("404") || message.includes("not enabled");

    results.push({
      checkId: "SEC-002",
      title: "Unresolved secret scanning alerts",
      severity: "CRITICAL",
      status: isNotEnabled ? "NOT_APPLICABLE" : "ERROR",
      resource,
      category: "secrets",
      details: isNotEnabled
        ? `Secret scanning alerts are not available for '${resource}'. Secret scanning may not be enabled or the repository may not be eligible.`
        : `Failed to list secret scanning alerts for '${resource}': ${message}`,
      remediation: isNotEnabled
        ? "Enable secret scanning first (see SEC-001)."
        : "Verify the token has repo and security_events scopes.",
    });
  }

  return results;
}
