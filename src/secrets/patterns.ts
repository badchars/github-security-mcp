import type { CheckResult } from "../types/index.js";
import type { GitHubClientFactory } from "../github/client.js";

/**
 * SEC-004: Custom secret scanning patterns
 */
export async function checkSecretPatterns(
  client: GitHubClientFactory,
  args: Record<string, unknown>,
): Promise<CheckResult[]> {
  const org = args.org as string;
  const results: CheckResult[] = [];

  try {
    const { data } = await client.rest().request(
      "GET /orgs/{org}/secret-scanning/custom-patterns",
      { org, per_page: 100 },
    );

    const patterns = Array.isArray(data) ? data : [];
    const count = patterns.length;

    const patternNames = patterns
      .slice(0, 10)
      .map((p: any) => p.name ?? "unnamed")
      .join(", ");

    results.push({
      checkId: "SEC-004",
      title: "No custom secret scanning patterns defined",
      severity: "LOW",
      status: count > 0 ? "PASS" : "FAIL",
      resource: `org/${org}`,
      category: "secrets",
      details:
        count > 0
          ? `Organization '${org}' has ${count} custom secret scanning pattern(s) defined${count <= 10 ? `: ${patternNames}` : ` (first 10: ${patternNames})`}. Custom patterns help detect organization-specific secrets.`
          : `Organization '${org}' has no custom secret scanning patterns defined. GitHub's built-in patterns cover common providers, but internal secrets (database passwords, internal API keys, custom tokens) will not be detected without custom patterns.`,
      remediation:
        "Define custom secret scanning patterns for organization-specific secrets. Go to Organization Settings > Code security and analysis > Custom patterns. Add patterns for internal API keys, database connection strings, and other proprietary secret formats.",
      reference:
        "https://docs.github.com/en/code-security/secret-scanning/using-advanced-secret-scanning-and-push-protection-features/custom-patterns-for-secret-scanning",
    });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    const isNotAvailable =
      message.includes("404") || message.includes("Not Found");

    results.push({
      checkId: "SEC-004",
      title: "No custom secret scanning patterns defined",
      severity: "LOW",
      status: isNotAvailable ? "NOT_APPLICABLE" : "ERROR",
      resource: `org/${org}`,
      category: "secrets",
      details: isNotAvailable
        ? `Custom secret scanning patterns API is not available for organization '${org}'. This feature requires GitHub Advanced Security.`
        : `Failed to check custom secret patterns for '${org}': ${message}`,
      remediation: isNotAvailable
        ? "Custom secret scanning patterns require GitHub Advanced Security. Consider upgrading."
        : "Verify the token has admin:org scope and the organization name is correct.",
      reference:
        "https://docs.github.com/en/code-security/secret-scanning/using-advanced-secret-scanning-and-push-protection-features/custom-patterns-for-secret-scanning",
    });
  }

  return results;
}
