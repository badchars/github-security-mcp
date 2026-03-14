import type { CheckResult } from "../types/index.js";
import type { GitHubClientFactory } from "../github/client.js";

/**
 * REPO-008: SECURITY.md presence check.
 * REPO-009: Private vulnerability reporting check.
 * REPO-010: Fork settings check for private repos.
 * Verifies general security-related repository settings.
 */
export async function checkRepoSettings(
  client: GitHubClientFactory,
  args: Record<string, unknown>,
): Promise<CheckResult[]> {
  const owner = args.owner as string;
  const repo = args.repo as string;
  const results: CheckResult[] = [];
  const resource = `${owner}/${repo}`;

  // REPO-008: Check for SECURITY.md
  try {
    const { data: metrics } = await client.rest().repos.getCommunityProfileMetrics({
      owner,
      repo,
    });

    const files = metrics.files as any;
    if (files?.security_policy) {
      results.push({
        checkId: "REPO-008",
        title: "Security policy (SECURITY.md) present",
        severity: "LOW",
        status: "PASS",
        resource,
        category: "repo",
        details: `Security policy found at: ${files.security_policy.html_url ?? "repository root or .github directory"}.`,
        remediation: "No action needed.",
        reference: "https://docs.github.com/en/code-security/getting-started/adding-a-security-policy-to-your-repository",
      });
    } else {
      results.push({
        checkId: "REPO-008",
        title: "No security policy (SECURITY.md)",
        severity: "LOW",
        status: "FAIL",
        resource,
        category: "repo",
        details: "No SECURITY.md file found. Security researchers have no documented way to report vulnerabilities responsibly.",
        remediation: "Add a SECURITY.md to the repository root or .github directory with instructions for reporting security vulnerabilities.",
        reference: "https://docs.github.com/en/code-security/getting-started/adding-a-security-policy-to-your-repository",
      });
    }
  } catch (err: any) {
    results.push({
      checkId: "REPO-008",
      title: "Security policy check failed",
      severity: "LOW",
      status: "ERROR",
      resource,
      category: "repo",
      details: `Failed to check community profile metrics: ${err.message}`,
      remediation: "Ensure the token has repo scope and the repository exists.",
    });
  }

  // REPO-009: Check private vulnerability reporting
  try {
    await client.rest().request(
      "GET /repos/{owner}/{repo}/private-vulnerability-reporting",
      { owner, repo },
    );
    // If the request succeeds, private vulnerability reporting is enabled
    results.push({
      checkId: "REPO-009",
      title: "Private vulnerability reporting enabled",
      severity: "LOW",
      status: "PASS",
      resource,
      category: "repo",
      details: "Private vulnerability reporting is enabled. Security researchers can confidentially report vulnerabilities.",
      remediation: "No action needed.",
      reference: "https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability",
    });
  } catch (err: any) {
    if (err.status === 404 || err.status === 422) {
      // 404 means the feature is not enabled or the endpoint is not available
      results.push({
        checkId: "REPO-009",
        title: "Private vulnerability reporting disabled",
        severity: "LOW",
        status: "FAIL",
        resource,
        category: "repo",
        details: "Private vulnerability reporting is not enabled. Security researchers cannot confidentially report vulnerabilities through GitHub's built-in mechanism.",
        remediation: "Enable private vulnerability reporting: Settings > Code security and analysis > Private vulnerability reporting > Enable.",
        reference: "https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability",
      });
    } else if (err.status === 403) {
      results.push({
        checkId: "REPO-009",
        title: "Private vulnerability reporting check not accessible",
        severity: "LOW",
        status: "NOT_APPLICABLE",
        resource,
        category: "repo",
        details: "Cannot check private vulnerability reporting status. The token may lack the required permissions.",
        remediation: "Ensure the token has admin:repo scope to check this setting.",
        reference: "https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability",
      });
    } else {
      results.push({
        checkId: "REPO-009",
        title: "Private vulnerability reporting check failed",
        severity: "LOW",
        status: "ERROR",
        resource,
        category: "repo",
        details: `Failed to check private vulnerability reporting: ${err.message}`,
        remediation: "Ensure the token has repo scope and the repository exists.",
      });
    }
  }

  // REPO-010: Check fork settings for org-owned private repos
  try {
    const { data: repoData } = await client.rest().repos.get({ owner, repo });

    if (!repoData.private) {
      results.push({
        checkId: "REPO-010",
        title: "Fork settings check skipped (public repo)",
        severity: "LOW",
        status: "NOT_APPLICABLE",
        resource,
        category: "repo",
        details: "This is a public repository. Fork restrictions are not applicable since public repos can always be forked.",
        remediation: "No action needed for public repositories.",
        reference: "https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/managing-repository-settings/managing-the-forking-policy-for-your-repository",
      });
    } else if (!repoData.organization) {
      results.push({
        checkId: "REPO-010",
        title: "Fork settings check skipped (user-owned repo)",
        severity: "LOW",
        status: "NOT_APPLICABLE",
        resource,
        category: "repo",
        details: "This is a user-owned private repository. Fork policy is managed at the user level.",
        remediation: "No action needed for user-owned private repositories.",
        reference: "https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/managing-repository-settings/managing-the-forking-policy-for-your-repository",
      });
    } else if (repoData.allow_forking) {
      results.push({
        checkId: "REPO-010",
        title: "Unrestricted fork settings on private repo",
        severity: "LOW",
        status: "FAIL",
        resource,
        category: "repo",
        details: "This organization-owned private repository allows forking. Organization members can fork this repo to their personal accounts, potentially exposing code outside the organization's control.",
        remediation: "Disable forking for this private repository: Settings > General > Forking > uncheck 'Allow forking'. Or configure at the org level: Organization Settings > Member privileges > Repository forking.",
        reference: "https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/managing-repository-settings/managing-the-forking-policy-for-your-repository",
      });
    } else {
      results.push({
        checkId: "REPO-010",
        title: "Fork settings restricted on private repo",
        severity: "LOW",
        status: "PASS",
        resource,
        category: "repo",
        details: "Forking is disabled on this organization-owned private repository. Code cannot be forked to personal accounts.",
        remediation: "No action needed.",
        reference: "https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/managing-repository-settings/managing-the-forking-policy-for-your-repository",
      });
    }
  } catch (err: any) {
    results.push({
      checkId: "REPO-010",
      title: "Fork settings check failed",
      severity: "LOW",
      status: "ERROR",
      resource,
      category: "repo",
      details: `Failed to check fork settings: ${err.message}`,
      remediation: "Ensure the token has repo scope and the repository exists.",
    });
  }

  return results;
}
