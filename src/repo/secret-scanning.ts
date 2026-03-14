import type { CheckResult } from "../types/index.js";
import type { GitHubClientFactory } from "../github/client.js";

/**
 * REPO-002: Secret scanning enabled check.
 * REPO-003: Push protection enabled check.
 * Verifies that secret scanning and push protection are active on the repository.
 */
export async function checkRepoSecretScanning(
  client: GitHubClientFactory,
  args: Record<string, unknown>,
): Promise<CheckResult[]> {
  const owner = args.owner as string;
  const repo = args.repo as string;
  const results: CheckResult[] = [];
  const resource = `${owner}/${repo}`;

  try {
    const { data: repoData } = await client.rest().repos.get({ owner, repo });
    const securityAnalysis = (repoData as any).security_and_analysis;

    // REPO-002: Secret scanning
    if (!securityAnalysis?.secret_scanning) {
      results.push({
        checkId: "REPO-002",
        title: "Secret scanning status unavailable",
        severity: "HIGH",
        status: "NOT_APPLICABLE",
        resource,
        category: "repo",
        details: "Secret scanning information is not available. This feature may not be supported on the current plan (requires GitHub Advanced Security for private repos).",
        remediation: "Upgrade to a plan that supports secret scanning, or enable it for public repositories in Settings > Code security and analysis.",
        reference: "https://docs.github.com/en/code-security/secret-scanning/about-secret-scanning",
      });
    } else if (securityAnalysis.secret_scanning.status !== "enabled") {
      results.push({
        checkId: "REPO-002",
        title: "Secret scanning not enabled",
        severity: "HIGH",
        status: "FAIL",
        resource,
        category: "repo",
        details: `Secret scanning is '${securityAnalysis.secret_scanning.status}'. Leaked secrets in commits will not be detected automatically.`,
        remediation: "Enable secret scanning: Settings > Code security and analysis > Secret scanning > Enable.",
        reference: "https://docs.github.com/en/code-security/secret-scanning/about-secret-scanning",
      });
    } else {
      results.push({
        checkId: "REPO-002",
        title: "Secret scanning enabled",
        severity: "HIGH",
        status: "PASS",
        resource,
        category: "repo",
        details: "Secret scanning is enabled. Leaked secrets in commits will be detected and flagged.",
        remediation: "No action needed.",
        reference: "https://docs.github.com/en/code-security/secret-scanning/about-secret-scanning",
      });
    }

    // REPO-003: Push protection
    if (!securityAnalysis?.secret_scanning_push_protection) {
      results.push({
        checkId: "REPO-003",
        title: "Push protection status unavailable",
        severity: "HIGH",
        status: "NOT_APPLICABLE",
        resource,
        category: "repo",
        details: "Push protection information is not available. This feature may not be supported on the current plan.",
        remediation: "Upgrade to a plan that supports push protection, or enable it for public repositories.",
        reference: "https://docs.github.com/en/code-security/secret-scanning/push-protection-for-repositories-and-organizations",
      });
    } else if (securityAnalysis.secret_scanning_push_protection.status !== "enabled") {
      results.push({
        checkId: "REPO-003",
        title: "Push protection not enabled",
        severity: "HIGH",
        status: "FAIL",
        resource,
        category: "repo",
        details: `Push protection is '${securityAnalysis.secret_scanning_push_protection.status}'. Developers can push commits containing secrets without being blocked.`,
        remediation: "Enable push protection: Settings > Code security and analysis > Push protection > Enable. This blocks pushes containing detected secrets.",
        reference: "https://docs.github.com/en/code-security/secret-scanning/push-protection-for-repositories-and-organizations",
      });
    } else {
      results.push({
        checkId: "REPO-003",
        title: "Push protection enabled",
        severity: "HIGH",
        status: "PASS",
        resource,
        category: "repo",
        details: "Push protection is enabled. Pushes containing detected secrets will be blocked.",
        remediation: "No action needed.",
        reference: "https://docs.github.com/en/code-security/secret-scanning/push-protection-for-repositories-and-organizations",
      });
    }
  } catch (err: any) {
    results.push({
      checkId: "REPO-002",
      title: "Secret scanning check failed",
      severity: "HIGH",
      status: "ERROR",
      resource,
      category: "repo",
      details: `Failed to check secret scanning: ${err.message}`,
      remediation: "Ensure the token has repo scope and the repository exists.",
    });
    results.push({
      checkId: "REPO-003",
      title: "Push protection check failed",
      severity: "HIGH",
      status: "ERROR",
      resource,
      category: "repo",
      details: `Failed to check push protection: ${err.message}`,
      remediation: "Ensure the token has repo scope and the repository exists.",
    });
  }

  return results;
}
