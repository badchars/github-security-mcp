import type { CheckResult } from "../types/index.js";
import type { GitHubClientFactory } from "../github/client.js";

/**
 * ACT-008: OIDC misconfiguration.
 *
 * GitHub Actions OIDC allows workflows to authenticate with cloud providers (AWS, Azure, GCP)
 * without long-lived credentials. Misconfigured OIDC subject claims can allow unauthorized
 * workflows or branches to assume cloud roles.
 */
export async function checkOidc(
  client: GitHubClientFactory,
  args: Record<string, unknown>,
): Promise<CheckResult[]> {
  const owner = args.owner as string;
  const repo = args.repo as string;
  const results: CheckResult[] = [];
  const resource = `${owner}/${repo}`;

  try {
    let oidcData: any;
    try {
      const { data } = await client.rest().request(
        "GET /repos/{owner}/{repo}/actions/oidc/customization/sub",
        { owner, repo },
      );
      oidcData = data;
    } catch (err: any) {
      if (err.status === 404) {
        results.push({
          checkId: "ACT-008",
          title: "OIDC not configured",
          severity: "MEDIUM",
          status: "NOT_APPLICABLE",
          resource,
          category: "actions",
          details: `Repository '${resource}' does not have OIDC subject claim customization configured. This may mean OIDC is not used or is using GitHub's defaults.`,
          remediation:
            "If this repo uses OIDC to authenticate with cloud providers, consider customizing the subject claim " +
            "to restrict which workflows/branches can assume cloud roles.",
          reference:
            "https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/about-security-hardening-with-openid-connect",
        });
        return results;
      }
      throw err;
    }

    const useDefault = oidcData.use_default ?? true;
    const includeClaimKeys: string[] = oidcData.include_claim_keys ?? [];

    const issues: string[] = [];

    // Check if using defaults without customization
    if (useDefault && includeClaimKeys.length === 0) {
      issues.push(
        "Using default OIDC subject claim without customization. The default claim format is " +
        "'repo:OWNER/REPO:ref:refs/heads/BRANCH' which may be too broad if your cloud IAM trusts " +
        "the entire repo rather than specific branches/environments.",
      );
    }

    // Check for overly broad claims
    if (includeClaimKeys.length > 0) {
      // If claims don't include restrictive fields like 'environment' or 'ref', flag it
      const hasEnvironment = includeClaimKeys.includes("environment");
      const hasRef = includeClaimKeys.includes("ref");
      const hasJobWorkflowRef = includeClaimKeys.includes("job_workflow_ref");

      if (!hasEnvironment && !hasRef && !hasJobWorkflowRef) {
        issues.push(
          `Custom claim keys [${includeClaimKeys.join(", ")}] do not include 'environment', 'ref', or 'job_workflow_ref'. ` +
          "Without these, any workflow in the repo can assume the cloud role, regardless of branch or environment.",
        );
      }
    }

    if (issues.length > 0) {
      results.push({
        checkId: "ACT-008",
        title: "OIDC subject claim may be overly broad",
        severity: "MEDIUM",
        status: "FAIL",
        resource,
        category: "actions",
        details:
          `OIDC configuration for '${resource}' has potential issues:\n- ${issues.join("\n- ")}`,
        remediation:
          "Customize the OIDC subject claim to include restrictive fields:\n\n" +
          "```\ngh api -X PUT /repos/OWNER/REPO/actions/oidc/customization/sub \\\n" +
          "  -f use_default=false \\\n" +
          '  -f include_claim_keys[]="repo" \\\n' +
          '  -f include_claim_keys[]="ref" \\\n' +
          '  -f include_claim_keys[]="environment"\n```\n\n' +
          "Then configure your cloud IAM role trust policy to match specific branches/environments.",
        reference:
          "https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/about-security-hardening-with-openid-connect#customizing-the-subject-claims",
      });
    } else {
      results.push({
        checkId: "ACT-008",
        title: "OIDC subject claim is customized",
        severity: "MEDIUM",
        status: "PASS",
        resource,
        category: "actions",
        details:
          `OIDC subject claim for '${resource}' includes restrictive claim keys: [${includeClaimKeys.join(", ")}].`,
        remediation: "No action needed.",
        reference:
          "https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/about-security-hardening-with-openid-connect#customizing-the-subject-claims",
      });
    }
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    results.push({
      checkId: "ACT-008",
      title: "OIDC check failed",
      severity: "MEDIUM",
      status: "ERROR",
      resource,
      category: "actions",
      details: `Failed to check OIDC configuration for '${resource}': ${message}`,
      remediation: "Ensure the token has repo and actions:read scopes.",
    });
  }

  return results;
}
