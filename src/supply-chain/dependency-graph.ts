import type { CheckResult } from "../types/index.js";
import type { GitHubClientFactory } from "../github/client.js";

/**
 * SUP-001: Dependency graph not enabled.
 *
 * The dependency graph is the foundation for GitHub's supply chain security features
 * (Dependabot alerts, security updates, SBOM export). Without it, the repository has
 * no visibility into its dependency tree or known vulnerabilities.
 */
export async function checkDependencyGraph(
  client: GitHubClientFactory,
  args: Record<string, unknown>,
): Promise<CheckResult[]> {
  const owner = args.owner as string;
  const repo = args.repo as string;
  const results: CheckResult[] = [];
  const resource = `${owner}/${repo}`;

  try {
    // First, check the repo's security_and_analysis settings
    const { data: repoData } = await client.rest().repos.get({ owner, repo });
    const securityAnalysis = (repoData as any).security_and_analysis;

    let dependencyGraphEnabled: boolean | null = null;

    if (securityAnalysis?.dependency_graph?.status) {
      dependencyGraphEnabled = securityAnalysis.dependency_graph.status === "enabled";
    }

    // If we couldn't determine from repo settings, try SBOM export as a probe
    if (dependencyGraphEnabled === null) {
      try {
        await client.rest().dependencyGraph.exportSbom({ owner, repo });
        dependencyGraphEnabled = true;
      } catch (err: any) {
        if (err.status === 404 || err.status === 403) {
          dependencyGraphEnabled = false;
        } else {
          // Unexpected error — report and continue
          dependencyGraphEnabled = null;
        }
      }
    }

    if (dependencyGraphEnabled === false) {
      results.push({
        checkId: "SUP-001",
        title: "Dependency graph not enabled",
        severity: "MEDIUM",
        status: "FAIL",
        resource,
        category: "supply-chain",
        details:
          `Repository '${resource}' does not have the dependency graph enabled. ` +
          "Without the dependency graph, Dependabot alerts and security updates cannot function, " +
          "and SBOM export is not available.",
        remediation:
          "Enable the dependency graph: Settings > Code security and analysis > Dependency graph > Enable.\n" +
          "For organizations, this can be enabled at the org level for all repositories.",
        reference:
          "https://docs.github.com/en/code-security/supply-chain-security/understanding-your-software-supply-chain/configuring-the-dependency-graph",
      });
    } else if (dependencyGraphEnabled === true) {
      results.push({
        checkId: "SUP-001",
        title: "Dependency graph is enabled",
        severity: "MEDIUM",
        status: "PASS",
        resource,
        category: "supply-chain",
        details: `Repository '${resource}' has the dependency graph enabled.`,
        remediation: "No action needed.",
        reference:
          "https://docs.github.com/en/code-security/supply-chain-security/understanding-your-software-supply-chain/configuring-the-dependency-graph",
      });
    } else {
      results.push({
        checkId: "SUP-001",
        title: "Dependency graph status unknown",
        severity: "MEDIUM",
        status: "ERROR",
        resource,
        category: "supply-chain",
        details:
          `Could not determine dependency graph status for '${resource}'. ` +
          "The API response did not include security_and_analysis data, and SBOM export probe was inconclusive.",
        remediation:
          "Verify the dependency graph status manually in Settings > Code security and analysis. " +
          "Ensure the token has repo scope.",
      });
    }
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    results.push({
      checkId: "SUP-001",
      title: "Dependency graph check failed",
      severity: "MEDIUM",
      status: "ERROR",
      resource,
      category: "supply-chain",
      details: `Failed to check dependency graph for '${resource}': ${message}`,
      remediation: "Ensure the token has repo scope and the repository exists.",
    });
  }

  return results;
}
