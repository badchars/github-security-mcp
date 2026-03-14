import type { CheckResult } from "../types/index.js";
import type { GitHubClientFactory } from "../github/client.js";

/**
 * ORG-009: Insecure webhook URLs (HTTP, insecure SSL)
 */
export async function checkOrgWebhooks(
  client: GitHubClientFactory,
  args: Record<string, unknown>,
): Promise<CheckResult[]> {
  const org = args.org as string;
  const results: CheckResult[] = [];

  try {
    const { data: hooks } = await client
      .rest()
      .orgs.listWebhooks({ org, per_page: 100 });

    if (hooks.length === 0) {
      results.push({
        checkId: "ORG-009",
        title: "Insecure webhook configuration",
        severity: "MEDIUM",
        status: "PASS",
        resource: `org/${org}`,
        category: "org",
        details: `Organization '${org}' has no webhooks configured.`,
        remediation: "No action needed.",
      });
      return results;
    }

    const insecureHooks: string[] = [];

    for (const hook of hooks) {
      const config = hook.config as Record<string, any> | undefined;
      if (!config) continue;

      const url = (config.url as string) ?? "";
      const insecureSsl = config.insecure_ssl;
      const issues: string[] = [];

      if (url.startsWith("http://")) {
        issues.push("uses HTTP (not HTTPS)");
      }
      if (insecureSsl === "1" || insecureSsl === 1) {
        issues.push("SSL verification disabled");
      }

      if (issues.length > 0) {
        const hookId = hook.id ?? "unknown";
        const hookName = hook.name ?? "web";
        insecureHooks.push(
          `hook ${hookId} (${hookName}, ${url}): ${issues.join(", ")}`,
        );
      }
    }

    results.push({
      checkId: "ORG-009",
      title: "Insecure webhook configuration",
      severity: "MEDIUM",
      status: insecureHooks.length > 0 ? "FAIL" : "PASS",
      resource: `org/${org}`,
      category: "org",
      details:
        insecureHooks.length > 0
          ? `Organization '${org}' has ${insecureHooks.length} insecure webhook(s) out of ${hooks.length} total: ${insecureHooks.join("; ")}. Webhooks using HTTP or with SSL verification disabled transmit event data (including secrets in payloads) in plaintext.`
          : `Organization '${org}' has ${hooks.length} webhook(s), all using HTTPS with SSL verification enabled.`,
      remediation:
        "Update webhook URLs to use HTTPS and enable SSL verification. Go to Organization Settings > Webhooks and edit each webhook.",
      reference:
        "https://docs.github.com/en/webhooks/using-webhooks/best-practices-for-using-webhooks",
    });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    results.push({
      checkId: "ORG-009",
      title: "Insecure webhook configuration",
      severity: "MEDIUM",
      status: "ERROR",
      resource: `org/${org}`,
      category: "org",
      details: `Failed to list webhooks for '${org}': ${message}`,
      remediation:
        "Verify the token has admin:org_hook scope and the organization name is correct.",
    });
  }

  return results;
}
