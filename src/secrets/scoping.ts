import type { CheckResult } from "../types/index.js";
import type { GitHubClientFactory } from "../github/client.js";

/**
 * SEC-005: Secret scoping analysis (repo-level and org-level Actions secrets)
 */
export async function checkSecretScoping(
  client: GitHubClientFactory,
  args: Record<string, unknown>,
): Promise<CheckResult[]> {
  const owner = args.owner as string;
  const repo = args.repo as string;
  const resource = `${owner}/${repo}`;
  const results: CheckResult[] = [];

  let repoSecretCount = 0;
  let repoSecretNames: string[] = [];
  let orgSecretCount = 0;
  let orgSecretNames: string[] = [];
  let orgCheckFailed = false;
  let repoCheckFailed = false;
  let repoError = "";
  let orgError = "";

  // Check repo-level secrets
  try {
    const { data } = await client
      .rest()
      .actions.listRepoSecrets({ owner, repo, per_page: 100 });

    const secrets = data.secrets ?? [];
    repoSecretCount = data.total_count ?? secrets.length;
    repoSecretNames = secrets
      .slice(0, 20)
      .map((s: any) => s.name);
  } catch (err: unknown) {
    repoCheckFailed = true;
    repoError = err instanceof Error ? err.message : String(err);
  }

  // Check org-level secrets (may fail if owner is a user, not an org)
  try {
    const { data } = await client
      .rest()
      .actions.listOrgSecrets({ org: owner, per_page: 100 });

    const secrets = data.secrets ?? [];
    orgSecretCount = data.total_count ?? secrets.length;
    orgSecretNames = secrets
      .slice(0, 20)
      .map((s: any) => s.name);
  } catch (err: unknown) {
    orgCheckFailed = true;
    orgError = err instanceof Error ? err.message : String(err);
  }

  // Build result
  if (repoCheckFailed && orgCheckFailed) {
    results.push({
      checkId: "SEC-005",
      title: "Overly broad secret scoping",
      severity: "MEDIUM",
      status: "ERROR",
      resource,
      category: "secrets",
      details: `Failed to check secret scoping for '${resource}'. Repo secrets error: ${repoError}. Org secrets error: ${orgError}`,
      remediation:
        "Verify the token has repo and admin:org scopes.",
    });
    return results;
  }

  const totalSecrets = repoSecretCount + orgSecretCount;
  const detailParts: string[] = [];

  if (!repoCheckFailed) {
    detailParts.push(
      `${repoSecretCount} repo-level secret(s)${repoSecretCount > 0 && repoSecretNames.length > 0 ? ` (${repoSecretNames.join(", ")})` : ""}`,
    );
  }

  if (!orgCheckFailed) {
    detailParts.push(
      `${orgSecretCount} org-level secret(s)${orgSecretCount > 0 && orgSecretNames.length > 0 ? ` (${orgSecretNames.join(", ")})` : ""}`,
    );
  } else {
    detailParts.push(
      "org-level secrets: not accessible (owner may be a user account, not an organization)",
    );
  }

  // Org-level secrets with broad visibility are a concern
  const hasBroadOrgSecrets = !orgCheckFailed && orgSecretCount > 0;

  results.push({
    checkId: "SEC-005",
    title: "Overly broad secret scoping",
    severity: "MEDIUM",
    status: hasBroadOrgSecrets ? "FAIL" : "PASS",
    resource,
    category: "secrets",
    details: hasBroadOrgSecrets
      ? `Repository '${resource}' has access to ${totalSecrets} Actions secret(s): ${detailParts.join("; ")}. Org-level secrets may be accessible to more repositories than intended. Follow the principle of least privilege by scoping secrets to specific repositories.`
      : `Repository '${resource}' has ${totalSecrets} Actions secret(s): ${detailParts.join("; ")}. No org-level secret exposure concerns detected.`,
    remediation:
      "Review secret scoping in Organization Settings > Secrets and variables > Actions. For org-level secrets, change visibility from 'All repositories' to 'Selected repositories'. Prefer repo-level or environment-level secrets when possible.",
    reference:
      "https://docs.github.com/en/actions/security-for-github-actions/security-guides/using-secrets-in-github-actions",
  });

  return results;
}
