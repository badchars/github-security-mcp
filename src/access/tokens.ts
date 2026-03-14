import type { CheckResult } from "../types/index.js";
import type { GitHubClientFactory } from "../github/client.js";

/**
 * ACC-004: Personal access token audit check.
 * Checks for fine-grained PATs via the org API. Classic PATs require audit log access.
 */
export async function checkTokenUsage(
  client: GitHubClientFactory,
  args: Record<string, unknown>,
): Promise<CheckResult[]> {
  const org = args.org as string | undefined;
  const results: CheckResult[] = [];

  if (!org) {
    results.push({
      checkId: "ACC-004",
      title: "Token audit requires organization",
      severity: "HIGH",
      status: "NOT_APPLICABLE",
      resource: "N/A",
      category: "access",
      details: "Token usage audit requires an organization name. This check cannot run without the 'org' parameter, as PAT enumeration is only available at the organization level.",
      remediation: "Provide the 'org' parameter to audit personal access tokens for an organization.",
      reference: "https://docs.github.com/en/organizations/managing-programmatic-access-to-your-organization/reviewing-and-revoking-personal-access-tokens-in-your-organization",
    });
    return results;
  }

  const resource = org;

  // Check fine-grained PATs via org API
  try {
    const { data: tokens } = await client.rest().request(
      "GET /orgs/{org}/personal-access-tokens",
      {
        org,
        per_page: 100,
      },
    );

    const tokenList = tokens as any[];

    if (tokenList.length === 0) {
      results.push({
        checkId: "ACC-004",
        title: "No fine-grained PATs found",
        severity: "HIGH",
        status: "PASS",
        resource,
        category: "access",
        details: `No fine-grained personal access tokens are authorized for organization '${org}'.`,
        remediation: "No action needed. Note: Classic PATs are not visible through this API. Check the audit log for classic PAT usage.",
        reference: "https://docs.github.com/en/organizations/managing-programmatic-access-to-your-organization/reviewing-and-revoking-personal-access-tokens-in-your-organization",
      });
    } else {
      // Analyze token permissions
      const allRepoTokens = tokenList.filter(
        (t: any) => t.repository_selection === "all",
      );
      const expiredTokens = tokenList.filter((t: any) => {
        if (!t.token_expired_at) return false;
        return new Date(t.token_expired_at) < new Date();
      });
      const noExpiryTokens = tokenList.filter(
        (t: any) => !t.token_expires_at,
      );

      const issues: string[] = [];

      if (allRepoTokens.length > 0) {
        issues.push(`${allRepoTokens.length} token(s) have access to ALL repositories`);
      }
      if (noExpiryTokens.length > 0) {
        issues.push(`${noExpiryTokens.length} token(s) have no expiration date`);
      }

      const tokenSummary = tokenList
        .slice(0, 10)
        .map((t: any) => {
          const owner = t.owner?.login ?? "unknown";
          const repoAccess = t.repository_selection ?? "unknown";
          const expires = t.token_expires_at
            ? new Date(t.token_expires_at).toISOString().split("T")[0]
            : "never";
          const permCount = t.permissions
            ? Object.keys(t.permissions).length
            : 0;
          return `- Owner: ${owner}, repos: ${repoAccess}, expires: ${expires}, permissions: ${permCount}`;
        })
        .join("\n");

      const hasConcerns = allRepoTokens.length > 0 || noExpiryTokens.length > 0;

      results.push({
        checkId: "ACC-004",
        title: hasConcerns
          ? "Fine-grained PATs with broad access found"
          : "Fine-grained PATs reviewed",
        severity: "HIGH",
        status: hasConcerns ? "FAIL" : "PASS",
        resource,
        category: "access",
        details: `Found ${tokenList.length} fine-grained PAT(s) authorized for organization '${org}'.${issues.length > 0 ? `\n\nConcerns:\n- ${issues.join("\n- ")}` : ""}\n\nTokens (first 10):\n${tokenSummary}${tokenList.length > 10 ? `\n... and ${tokenList.length - 10} more` : ""}\n\nNote: Classic PATs are not visible through this API. Check the organization audit log for classic PAT usage: https://github.com/organizations/${org}/settings/audit-log?q=action:integration.access_token`,
        remediation: hasConcerns
          ? "Review tokens with 'all repository' access and reduce scope to specific repositories. Set expiration dates on tokens without them. Organization Settings > Personal access tokens > Active tokens."
          : "No action needed. Periodically review authorized PATs.",
        reference: "https://docs.github.com/en/organizations/managing-programmatic-access-to-your-organization/reviewing-and-revoking-personal-access-tokens-in-your-organization",
      });
    }
  } catch (err: any) {
    if (err.status === 404 || err.status === 403) {
      results.push({
        checkId: "ACC-004",
        title: "Token audit not accessible",
        severity: "HIGH",
        status: "NOT_APPLICABLE",
        resource,
        category: "access",
        details: `Cannot access PAT information for organization '${org}' (HTTP ${err.status}). This API requires organization owner permissions and the token must have 'admin:org' scope. Fine-grained PAT management may not be enabled for this organization.`,
        remediation: "Ensure the token has admin:org scope and is owned by an organization owner. Enable fine-grained PAT management in Organization Settings > Personal access tokens > Settings.",
        reference: "https://docs.github.com/en/organizations/managing-programmatic-access-to-your-organization/reviewing-and-revoking-personal-access-tokens-in-your-organization",
      });
    } else {
      results.push({
        checkId: "ACC-004",
        title: "Token audit check failed",
        severity: "HIGH",
        status: "ERROR",
        resource,
        category: "access",
        details: `Failed to audit personal access tokens: ${err.message}`,
        remediation: "Ensure the token has admin:org scope.",
      });
    }
  }

  // Supplementary: try to check audit log for classic PAT usage
  try {
    const { data: auditEvents } = await client.rest().request(
      "GET /orgs/{org}/audit-log",
      {
        org,
        phrase: "action:personal_access_token",
        per_page: 10,
      },
    );

    const events = auditEvents as any[];
    if (events.length > 0) {
      const eventSummary = events
        .slice(0, 5)
        .map((e: any) => `- ${e.action} by ${e.actor ?? "unknown"} at ${e["@timestamp"] ?? e.created_at ?? "unknown"}`)
        .join("\n");

      results.push({
        checkId: "ACC-004",
        title: "Classic PAT audit log activity detected",
        severity: "HIGH",
        status: "FAIL",
        resource,
        category: "access",
        details: `Found ${events.length} recent audit log entries related to personal access tokens.\n\nRecent events:\n${eventSummary}\n\nClassic PATs with broad scopes (repo, admin:org, etc.) are a significant security risk. Fine-grained PATs are recommended.`,
        remediation: "Encourage migration from classic PATs to fine-grained PATs. Enable fine-grained PAT requirement in Organization Settings > Personal access tokens > Settings > Require fine-grained personal access tokens.",
        reference: "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens",
      });
    }
  } catch {
    // Audit log access is restricted to Enterprise — silently skip
  }

  return results;
}
