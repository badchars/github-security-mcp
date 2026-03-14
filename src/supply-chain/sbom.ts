import type { CheckResult } from "../types/index.js";
import type { GitHubClientFactory } from "../github/client.js";

/**
 * SUP-003: No SBOM generation.
 *
 * A Software Bill of Materials (SBOM) provides a complete inventory of all dependencies,
 * enabling vulnerability tracking, license compliance, and supply chain risk assessment.
 * GitHub can export SBOMs in SPDX format when the dependency graph is enabled.
 */
export async function checkSbom(
  client: GitHubClientFactory,
  args: Record<string, unknown>,
): Promise<CheckResult[]> {
  const owner = args.owner as string;
  const repo = args.repo as string;
  const results: CheckResult[] = [];
  const resource = `${owner}/${repo}`;

  try {
    const { data } = await client.rest().dependencyGraph.exportSbom({ owner, repo });

    // SBOM exported successfully — check if it has meaningful content
    const sbom = data.sbom as any;
    const packageCount = sbom?.packages?.length ?? 0;

    results.push({
      checkId: "SUP-003",
      title: "SBOM generation available",
      severity: "LOW",
      status: "PASS",
      resource,
      category: "supply-chain",
      details:
        `Repository '${resource}' supports SBOM export (SPDX format). ` +
        `The dependency graph contains ${packageCount} package(s).`,
      remediation: "No action needed.",
      reference:
        "https://docs.github.com/en/code-security/supply-chain-security/understanding-your-software-supply-chain/exporting-a-software-bill-of-materials-for-your-repository",
    });
  } catch (err: any) {
    if (err.status === 404 || err.status === 403) {
      results.push({
        checkId: "SUP-003",
        title: "SBOM generation not available",
        severity: "LOW",
        status: "FAIL",
        resource,
        category: "supply-chain",
        details:
          `Repository '${resource}' cannot export an SBOM. This typically means the dependency graph ` +
          "is not enabled, or the repository has no detectable dependencies.",
        remediation:
          "Enable the dependency graph first: Settings > Code security and analysis > Dependency graph > Enable.\n" +
          "Once enabled, GitHub will automatically detect dependencies and make SBOM export available.\n" +
          "You can then export via: `gh api /repos/OWNER/REPO/dependency-graph/sbom`",
        reference:
          "https://docs.github.com/en/code-security/supply-chain-security/understanding-your-software-supply-chain/exporting-a-software-bill-of-materials-for-your-repository",
      });
    } else {
      const message = err instanceof Error ? err.message : String(err);
      results.push({
        checkId: "SUP-003",
        title: "SBOM check failed",
        severity: "LOW",
        status: "ERROR",
        resource,
        category: "supply-chain",
        details: `Failed to export SBOM for '${resource}': ${message}`,
        remediation: "Ensure the token has repo scope and the repository exists.",
      });
    }
  }

  return results;
}
