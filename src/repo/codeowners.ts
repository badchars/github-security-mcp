import type { CheckResult } from "../types/index.js";
import type { GitHubClientFactory } from "../github/client.js";

/**
 * REPO-013: CODEOWNERS file presence check.
 * Verifies that a CODEOWNERS file exists in one of the standard locations.
 */
export async function checkCodeowners(
  client: GitHubClientFactory,
  args: Record<string, unknown>,
): Promise<CheckResult[]> {
  const owner = args.owner as string;
  const repo = args.repo as string;
  const results: CheckResult[] = [];
  const resource = `${owner}/${repo}`;

  const codeownersPaths = [
    ".github/CODEOWNERS",
    "CODEOWNERS",
    "docs/CODEOWNERS",
  ];

  let foundPath: string | null = null;

  for (const path of codeownersPaths) {
    try {
      await client.rest().repos.getContent({ owner, repo, path });
      foundPath = path;
      break;
    } catch (err: any) {
      if (err.status === 404) {
        continue;
      }
      // Non-404 error means something unexpected happened
      results.push({
        checkId: "REPO-013",
        title: "CODEOWNERS check failed",
        severity: "LOW",
        status: "ERROR",
        resource,
        category: "repo",
        details: `Failed to check for CODEOWNERS at '${path}': ${err.message}`,
        remediation: "Ensure the token has repo scope.",
      });
      return results;
    }
  }

  if (foundPath) {
    results.push({
      checkId: "REPO-013",
      title: "CODEOWNERS file present",
      severity: "LOW",
      status: "PASS",
      resource,
      category: "repo",
      details: `CODEOWNERS file found at '${foundPath}'. Code review ownership is defined.`,
      remediation: "No action needed. Ensure the CODEOWNERS file is kept up to date with current team structure.",
      reference: "https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners",
    });
  } else {
    results.push({
      checkId: "REPO-013",
      title: "Missing CODEOWNERS file",
      severity: "LOW",
      status: "FAIL",
      resource,
      category: "repo",
      details: `No CODEOWNERS file found in any standard location (${codeownersPaths.join(", ")}). Without CODEOWNERS, there is no enforced code review ownership.`,
      remediation: "Create a CODEOWNERS file in .github/CODEOWNERS, the repository root, or docs/CODEOWNERS. Define code review owners for critical paths.",
      reference: "https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners",
    });
  }

  return results;
}
