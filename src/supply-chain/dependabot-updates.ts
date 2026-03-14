import type { CheckResult } from "../types/index.js";
import type { GitHubClientFactory } from "../github/client.js";

/**
 * SUP-002: Dependabot security updates disabled.
 *
 * Dependabot security updates automatically open PRs to fix known vulnerabilities in
 * dependencies. Without them, the repository relies on manual monitoring and patching,
 * which often leads to stale, vulnerable dependencies.
 */
export async function checkDependabotUpdates(
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

    // Check Dependabot security updates
    const securityUpdatesStatus =
      securityAnalysis?.dependabot_security_updates?.status ?? "disabled";

    if (securityUpdatesStatus !== "enabled") {
      results.push({
        checkId: "SUP-002",
        title: "Dependabot security updates disabled",
        severity: "HIGH",
        status: "FAIL",
        resource,
        category: "supply-chain",
        details:
          `Repository '${resource}' does not have Dependabot security updates enabled (status: '${securityUpdatesStatus}'). ` +
          "Known vulnerable dependencies will not be automatically patched.",
        remediation:
          "Enable Dependabot security updates: Settings > Code security and analysis > Dependabot security updates > Enable.\n" +
          "This requires the dependency graph to be enabled first.",
        reference:
          "https://docs.github.com/en/code-security/dependabot/dependabot-security-updates/configuring-dependabot-security-updates",
      });
    } else {
      results.push({
        checkId: "SUP-002",
        title: "Dependabot security updates enabled",
        severity: "HIGH",
        status: "PASS",
        resource,
        category: "supply-chain",
        details: `Repository '${resource}' has Dependabot security updates enabled.`,
        remediation: "No action needed.",
        reference:
          "https://docs.github.com/en/code-security/dependabot/dependabot-security-updates/configuring-dependabot-security-updates",
      });
    }

    // Check for Dependabot version updates configuration (dependabot.yml)
    let hasDependabotConfig = false;
    try {
      await client.rest().repos.getContent({
        owner,
        repo,
        path: ".github/dependabot.yml",
      });
      hasDependabotConfig = true;
    } catch {
      // Try .yaml extension
      try {
        await client.rest().repos.getContent({
          owner,
          repo,
          path: ".github/dependabot.yaml",
        });
        hasDependabotConfig = true;
      } catch {
        /* no dependabot config */
      }
    }

    if (!hasDependabotConfig) {
      results.push({
        checkId: "SUP-002b",
        title: "Dependabot version updates not configured",
        severity: "HIGH",
        status: "FAIL",
        resource,
        category: "supply-chain",
        details:
          `Repository '${resource}' does not have a .github/dependabot.yml configuration file. ` +
          "Without version updates, dependencies will only be updated for security fixes (if security updates are enabled), " +
          "not for regular version bumps that may include important fixes and improvements.",
        remediation:
          "Create a .github/dependabot.yml file to configure automated dependency version updates:\n\n" +
          "```yaml\nversion: 2\nupdates:\n  - package-ecosystem: \"npm\"  # or pip, docker, etc.\n" +
          "    directory: \"/\"\n    schedule:\n      interval: \"weekly\"\n```",
        reference:
          "https://docs.github.com/en/code-security/dependabot/dependabot-version-updates/configuring-dependabot-version-updates",
      });
    } else {
      results.push({
        checkId: "SUP-002b",
        title: "Dependabot version updates configured",
        severity: "HIGH",
        status: "PASS",
        resource,
        category: "supply-chain",
        details: `Repository '${resource}' has a Dependabot configuration file for version updates.`,
        remediation: "No action needed.",
        reference:
          "https://docs.github.com/en/code-security/dependabot/dependabot-version-updates/configuring-dependabot-version-updates",
      });
    }
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    results.push({
      checkId: "SUP-002",
      title: "Dependabot updates check failed",
      severity: "HIGH",
      status: "ERROR",
      resource,
      category: "supply-chain",
      details: `Failed to check Dependabot configuration for '${resource}': ${message}`,
      remediation: "Ensure the token has repo scope and the repository exists.",
    });
  }

  return results;
}
