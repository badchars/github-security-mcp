import type { CheckResult } from "../types/index.js";
import type { GitHubClientFactory } from "../github/client.js";

/**
 * REPO-012: Deploy key permissions check.
 * Flags deploy keys that have read-write access, which is a higher risk than read-only.
 */
export async function checkDeployKeys(
  client: GitHubClientFactory,
  args: Record<string, unknown>,
): Promise<CheckResult[]> {
  const owner = args.owner as string;
  const repo = args.repo as string;
  const results: CheckResult[] = [];
  const resource = `${owner}/${repo}`;

  try {
    const { data: keys } = await client.rest().repos.listDeployKeys({
      owner,
      repo,
      per_page: 100,
    });

    if (keys.length === 0) {
      results.push({
        checkId: "REPO-012",
        title: "No deploy keys configured",
        severity: "HIGH",
        status: "PASS",
        resource,
        category: "repo",
        details: "No deploy keys are configured on this repository.",
        remediation: "No action needed.",
        reference: "https://docs.github.com/en/authentication/connecting-to-github-with-ssh/managing-deploy-keys",
      });
      return results;
    }

    const readWriteKeys = keys.filter((k) => !k.read_only);
    const readOnlyKeys = keys.filter((k) => k.read_only);

    if (readWriteKeys.length > 0) {
      const keyList = readWriteKeys
        .map((k) => {
          const createdAt = k.created_at ? new Date(k.created_at).toISOString().split("T")[0] : "unknown";
          return `- "${k.title}" (id: ${k.id}, created: ${createdAt})`;
        })
        .join("\n");

      results.push({
        checkId: "REPO-012",
        title: "Read-write deploy keys found",
        severity: "HIGH",
        status: "FAIL",
        resource,
        category: "repo",
        details: `Found ${readWriteKeys.length} deploy key(s) with read-write access (out of ${keys.length} total). Read-write keys can push code to the repository, increasing the blast radius if compromised.\n\nRead-write keys:\n${keyList}`,
        remediation: "Review each read-write deploy key. If write access is not required, delete the key and recreate it as read-only. Settings > Deploy keys > remove and re-add as read-only.",
        reference: "https://docs.github.com/en/authentication/connecting-to-github-with-ssh/managing-deploy-keys",
      });
    } else {
      results.push({
        checkId: "REPO-012",
        title: "All deploy keys are read-only",
        severity: "HIGH",
        status: "PASS",
        resource,
        category: "repo",
        details: `All ${readOnlyKeys.length} deploy key(s) are read-only. No keys have write access.`,
        remediation: "No action needed.",
        reference: "https://docs.github.com/en/authentication/connecting-to-github-with-ssh/managing-deploy-keys",
      });
    }
  } catch (err: any) {
    if (err.status === 404 || err.status === 403) {
      results.push({
        checkId: "REPO-012",
        title: "Deploy keys check not accessible",
        severity: "HIGH",
        status: "NOT_APPLICABLE",
        resource,
        category: "repo",
        details: `Cannot access deploy keys (HTTP ${err.status}). The token may lack the required permissions.`,
        remediation: "Ensure the token has repo scope to list deploy keys.",
        reference: "https://docs.github.com/en/authentication/connecting-to-github-with-ssh/managing-deploy-keys",
      });
    } else {
      results.push({
        checkId: "REPO-012",
        title: "Deploy keys check failed",
        severity: "HIGH",
        status: "ERROR",
        resource,
        category: "repo",
        details: `Failed to check deploy keys: ${err.message}`,
        remediation: "Ensure the token has repo scope.",
      });
    }
  }

  return results;
}
