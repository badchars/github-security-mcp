import type { CheckResult } from "../types/index.js";
import type { GitHubClientFactory } from "../github/client.js";

/**
 * SEC-003: Push protection bypass detection
 */
export async function checkPushProtection(
  client: GitHubClientFactory,
  args: Record<string, unknown>,
): Promise<CheckResult[]> {
  const owner = args.owner as string;
  const repo = args.repo as string;
  const resource = `${owner}/${repo}`;
  const results: CheckResult[] = [];

  try {
    const { data: alerts } = await client
      .rest()
      .secretScanning.listAlertsForRepo({
        owner,
        repo,
        per_page: 100,
      });

    const bypassed = alerts.filter(
      (a: any) => a.push_protection_bypassed === true,
    );

    const count = bypassed.length;
    const bypassDetails = bypassed.slice(0, 10).map((a: any) => {
      const secretType =
        a.secret_type_display_name ?? a.secret_type ?? "unknown";
      const bypassedBy = a.push_protection_bypassed_by?.login ?? "unknown";
      const bypassedAt = a.push_protection_bypassed_at ?? "unknown time";
      return `${secretType} bypassed by ${bypassedBy} at ${bypassedAt}`;
    });

    results.push({
      checkId: "SEC-003",
      title: "Push protection bypasses detected",
      severity: "HIGH",
      status: count > 0 ? "FAIL" : "PASS",
      resource,
      category: "secrets",
      details:
        count > 0
          ? `Repository '${resource}' has ${count} push protection bypass(es). ${bypassDetails.length <= 10 ? `Bypasses: ${bypassDetails.join("; ")}` : `First 10: ${bypassDetails.join("; ")} (and ${count - 10} more)`}. Each bypass represents a deliberate decision to push a detected secret.`
          : `Repository '${resource}' has no push protection bypasses detected.`,
      remediation:
        "Review each push protection bypass. Rotate the bypassed secrets and investigate why the bypass was approved. Consider restricting who can bypass push protection in Repository Settings > Code security and analysis.",
      reference:
        "https://docs.github.com/en/code-security/secret-scanning/using-advanced-secret-scanning-and-push-protection-features/push-protection-for-repositories-and-organizations",
    });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    const isNotEnabled =
      message.includes("404") || message.includes("not enabled");

    results.push({
      checkId: "SEC-003",
      title: "Push protection bypasses detected",
      severity: "HIGH",
      status: isNotEnabled ? "NOT_APPLICABLE" : "ERROR",
      resource,
      category: "secrets",
      details: isNotEnabled
        ? `Secret scanning is not available for '${resource}'. Push protection bypass detection requires secret scanning to be enabled.`
        : `Failed to check push protection bypasses for '${resource}': ${message}`,
      remediation: isNotEnabled
        ? "Enable secret scanning and push protection first."
        : "Verify the token has repo and security_events scopes.",
      reference:
        "https://docs.github.com/en/code-security/secret-scanning/using-advanced-secret-scanning-and-push-protection-features/push-protection-for-repositories-and-organizations",
    });
  }

  return results;
}
