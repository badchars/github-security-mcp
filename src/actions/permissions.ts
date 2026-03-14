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

/**
 * Check whether a workflow YAML has a top-level `permissions:` key.
 * A top-level permissions key means the workflow explicitly declares its token scope.
 */
function hasTopLevelPermissions(content: string): boolean {
  const lines = content.split("\n");
  for (const line of lines) {
    // Top-level key: starts at column 0 (no leading whitespace)
    if (/^permissions\s*:/i.test(line)) {
      return true;
    }
  }
  return false;
}

/**
 * ACT-003: Over-permissive GITHUB_TOKEN defaults.
 *
 * Checks the repository's default workflow permissions setting and whether individual
 * workflows declare explicit `permissions:` blocks to restrict the GITHUB_TOKEN scope.
 */
export async function checkWorkflowPermissions(
  client: GitHubClientFactory,
  args: Record<string, unknown>,
): Promise<CheckResult[]> {
  const owner = args.owner as string;
  const repo = args.repo as string;
  const results: CheckResult[] = [];
  const resource = `${owner}/${repo}`;

  try {
    // Check repo-level default workflow permissions
    const { data: permData } = await client.rest().request(
      "GET /repos/{owner}/{repo}/actions/permissions",
      { owner, repo },
    ) as { data: { default_workflow_permissions?: string; can_approve_pull_request_reviews?: boolean } };

    const defaultPerms = permData.default_workflow_permissions ?? "write";
    const canApprovePR = permData.can_approve_pull_request_reviews ?? false;

    if (defaultPerms === "write") {
      results.push({
        checkId: "ACT-003",
        title: "Default GITHUB_TOKEN has write permissions",
        severity: "HIGH",
        status: "FAIL",
        resource,
        category: "actions",
        details:
          `Repository '${resource}' default workflow permissions are set to 'write'. ` +
          `All workflows without explicit 'permissions:' blocks get full write access to the repo, ` +
          `including pushing code, creating releases, and modifying issues/PRs.`,
        remediation:
          "Go to Settings > Actions > General > Workflow permissions and select 'Read repository contents and packages permissions'. " +
          "Then add explicit `permissions:` blocks to workflows that need write access.",
        reference:
          "https://docs.github.com/en/actions/security-for-github-actions/security-guides/automatic-token-authentication#modifying-the-permissions-for-the-github_token",
      });
    } else {
      results.push({
        checkId: "ACT-003",
        title: "Default GITHUB_TOKEN permissions are restricted",
        severity: "HIGH",
        status: "PASS",
        resource,
        category: "actions",
        details: `Repository '${resource}' default workflow permissions are set to '${defaultPerms}'.`,
        remediation: "No action needed.",
        reference:
          "https://docs.github.com/en/actions/security-for-github-actions/security-guides/automatic-token-authentication#modifying-the-permissions-for-the-github_token",
      });
    }

    if (canApprovePR) {
      results.push({
        checkId: "ACT-003",
        title: "GITHUB_TOKEN can approve pull request reviews",
        severity: "HIGH",
        status: "FAIL",
        resource,
        category: "actions",
        details:
          `Repository '${resource}' allows the GITHUB_TOKEN to approve pull request reviews. ` +
          `This means automated workflows can self-approve PRs, bypassing human review requirements.`,
        remediation:
          "Go to Settings > Actions > General > Workflow permissions and uncheck " +
          "'Allow GitHub Actions to create and approve pull requests'.",
        reference:
          "https://docs.github.com/en/actions/security-for-github-actions/security-guides/automatic-token-authentication",
      });
    }

    // Check individual workflows for missing permissions declarations
    const workflows = await getWorkflowFiles(client, owner, repo);
    const missingPerms: string[] = [];

    for (const wf of workflows) {
      if (!hasTopLevelPermissions(wf.content)) {
        missingPerms.push(wf.name);
      }
    }

    if (missingPerms.length > 0 && defaultPerms === "write") {
      results.push({
        checkId: "ACT-003",
        title: "Workflows without explicit permissions inherit write default",
        severity: "HIGH",
        status: "FAIL",
        resource,
        category: "actions",
        details:
          `${missingPerms.length} workflow(s) do not declare top-level 'permissions:' and inherit the repo default ('write'):\n` +
          `- ${missingPerms.join("\n- ")}`,
        remediation:
          "Add a top-level `permissions:` block to each workflow to restrict the GITHUB_TOKEN scope. " +
          "For example:\n\n```yaml\npermissions:\n  contents: read\n```",
        reference:
          "https://docs.github.com/en/actions/writing-workflows/choosing-what-your-workflow-does/controlling-permissions-for-github_token",
      });
    }
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    results.push({
      checkId: "ACT-003",
      title: "Over-permissive GITHUB_TOKEN defaults",
      severity: "HIGH",
      status: "ERROR",
      resource,
      category: "actions",
      details: `Failed to check workflow permissions for '${resource}': ${message}`,
      remediation: "Ensure the token has repo and actions:read scopes.",
    });
  }

  return results;
}
