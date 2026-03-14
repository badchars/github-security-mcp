import type { CheckResult } from "../types/index.js";
import type { GitHubClientFactory } from "../github/client.js";

/**
 * Fetch all workflow YAML files from a repository's .github/workflows directory.
 */
async function getWorkflowFiles(
  client: GitHubClientFactory,
  owner: string,
  repo: string,
): Promise<Array<{ name: string; content: string }>> {
  const octokit = client.rest();
  const workflows: Array<{ name: string; content: string }> = [];
  try {
    const { data } = await octokit.repos.getContent({ owner, repo, path: ".github/workflows" });
    if (!Array.isArray(data)) return workflows;
    for (const file of data) {
      if (!file.name.endsWith(".yml") && !file.name.endsWith(".yaml")) continue;
      try {
        const { data: fileData } = await octokit.repos.getContent({ owner, repo, path: file.path });
        if ("content" in fileData && fileData.content) {
          workflows.push({
            name: file.name,
            content: Buffer.from(fileData.content, "base64").toString("utf-8"),
          });
        }
      } catch {
        /* skip unreadable files */
      }
    }
  } catch {
    /* no workflows directory */
  }
  return workflows;
}

const USES_PATTERN = /uses:\s+([^@\s]+)@([^\s#]+)/g;
const SHA_PATTERN = /^[0-9a-f]{40}$/i;
const GITHUB_OWNED_PREFIXES = ["actions/", "github/"];

/**
 * ACT-004: Unpinned third-party actions.
 *
 * Third-party actions referenced by mutable tag (v1, main, latest) can be silently modified
 * by the action author. A compromised or malicious tag update can inject code into CI pipelines.
 * SHA-pinning ensures reproducible and tamper-evident builds.
 */
export async function checkActionPinning(
  client: GitHubClientFactory,
  args: Record<string, unknown>,
): Promise<CheckResult[]> {
  const owner = args.owner as string;
  const repo = args.repo as string;
  const results: CheckResult[] = [];
  const resource = `${owner}/${repo}`;

  try {
    const workflows = await getWorkflowFiles(client, owner, repo);

    if (workflows.length === 0) {
      results.push({
        checkId: "ACT-004",
        title: "Unpinned third-party actions",
        severity: "MEDIUM",
        status: "NOT_APPLICABLE",
        resource,
        category: "actions",
        details: "No workflow files found in .github/workflows/.",
        remediation: "No action needed — no workflows to audit.",
      });
      return results;
    }

    const unpinnedActions: Array<{ workflow: string; action: string; version: string }> = [];

    for (const wf of workflows) {
      USES_PATTERN.lastIndex = 0;
      let match: RegExpExecArray | null;
      while ((match = USES_PATTERN.exec(wf.content)) !== null) {
        const actionRef = match[1];
        const version = match[2];

        // Skip GitHub-owned actions
        const isGitHubOwned = GITHUB_OWNED_PREFIXES.some((prefix) => actionRef.startsWith(prefix));
        if (isGitHubOwned) continue;

        // Skip local actions (./path)
        if (actionRef.startsWith("./")) continue;

        // Check if pinned to SHA
        if (!SHA_PATTERN.test(version)) {
          unpinnedActions.push({ workflow: wf.name, action: actionRef, version });
        }
      }
    }

    if (unpinnedActions.length > 0) {
      const grouped = new Map<string, Array<{ action: string; version: string }>>();
      for (const item of unpinnedActions) {
        const list = grouped.get(item.workflow) ?? [];
        list.push({ action: item.action, version: item.version });
        grouped.set(item.workflow, list);
      }

      const detailLines: string[] = [];
      for (const [wfName, actions] of grouped) {
        for (const a of actions) {
          detailLines.push(`${wfName}: ${a.action}@${a.version}`);
        }
      }

      results.push({
        checkId: "ACT-004",
        title: "Unpinned third-party actions",
        severity: "MEDIUM",
        status: "FAIL",
        resource,
        category: "actions",
        details:
          `Found ${unpinnedActions.length} third-party action(s) not pinned to a full SHA commit hash:\n- ${detailLines.join("\n- ")}`,
        remediation:
          "Pin all third-party actions to a full commit SHA instead of a mutable tag. Example:\n\n" +
          "```yaml\n# Bad — mutable tag\nuses: some-org/some-action@v1\n\n" +
          "# Good — SHA-pinned\nuses: some-org/some-action@abc123def456...  # v1.2.3\n```\n\n" +
          "Use `gh api /repos/OWNER/REPO/git/ref/tags/TAG` to resolve a tag to its commit SHA. " +
          "Tools like Dependabot or Renovate can automate SHA pin updates.",
        reference: "https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#using-third-party-actions",
      });
    } else {
      results.push({
        checkId: "ACT-004",
        title: "All third-party actions are SHA-pinned",
        severity: "MEDIUM",
        status: "PASS",
        resource,
        category: "actions",
        details: `Scanned ${workflows.length} workflow file(s) — all third-party action references use full SHA commit hashes.`,
        remediation: "No action needed.",
        reference: "https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#using-third-party-actions",
      });
    }
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    results.push({
      checkId: "ACT-004",
      title: "Unpinned third-party actions",
      severity: "MEDIUM",
      status: "ERROR",
      resource,
      category: "actions",
      details: `Failed to check action pinning for '${resource}': ${message}`,
      remediation: "Ensure the token has repo/contents:read scope and the repository exists.",
    });
  }

  return results;
}
