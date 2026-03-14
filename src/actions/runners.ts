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

const SELF_HOSTED_PATTERN = /runs-on:.*self-hosted/gi;

/**
 * ACT-005: Self-hosted runner exposure.
 *
 * Self-hosted runners persist between jobs by default, meaning malware, credentials,
 * or backdoors from one workflow run can affect subsequent runs. Particularly dangerous
 * when used with public repositories where any fork can trigger workflows.
 */
export async function checkRunners(
  client: GitHubClientFactory,
  args: Record<string, unknown>,
): Promise<CheckResult[]> {
  const org = args.org as string | undefined;
  const owner = args.owner as string | undefined;
  const repo = args.repo as string | undefined;
  const results: CheckResult[] = [];

  try {
    // Check for registered self-hosted runners via API
    if (org) {
      const resource = `org/${org}`;
      try {
        const { data } = await client.rest().actions.listSelfHostedRunnersForOrg({
          org,
          per_page: 100,
        });

        if (data.total_count > 0) {
          const runnerNames = data.runners.map(
            (r: any) => `${r.name} (${r.os}, status: ${r.status})`,
          );
          results.push({
            checkId: "ACT-005",
            title: "Self-hosted runners registered at org level",
            severity: "HIGH",
            status: "FAIL",
            resource,
            category: "actions",
            details:
              `Organization '${org}' has ${data.total_count} self-hosted runner(s) registered. ` +
              `Self-hosted runners persist state between jobs, risking credential theft, crypto mining, and lateral movement.\n` +
              `Runners:\n- ${runnerNames.join("\n- ")}`,
            remediation:
              "1. Use ephemeral runners (--ephemeral flag) that are destroyed after each job.\n" +
              "2. Never use self-hosted runners on public repositories.\n" +
              "3. Restrict runner groups to specific repositories.\n" +
              "4. Use runner groups with limited repository access in Organization Settings > Actions > Runner groups.",
            reference:
              "https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/about-self-hosted-runners#self-hosted-runner-security",
          });
        } else {
          results.push({
            checkId: "ACT-005",
            title: "No self-hosted runners at org level",
            severity: "HIGH",
            status: "PASS",
            resource,
            category: "actions",
            details: `Organization '${org}' has no self-hosted runners registered.`,
            remediation: "No action needed.",
          });
        }
      } catch (err: any) {
        if (err.status === 404 || err.status === 403) {
          results.push({
            checkId: "ACT-005",
            title: "Self-hosted runner check — insufficient permissions",
            severity: "HIGH",
            status: "ERROR",
            resource,
            category: "actions",
            details: `Cannot list self-hosted runners for org '${org}': ${err.message}`,
            remediation: "Ensure the token has admin:org scope to list self-hosted runners.",
          });
        } else {
          throw err;
        }
      }
    }

    if (owner && repo) {
      const resource = `${owner}/${repo}`;

      // Check for repo-level self-hosted runners
      try {
        const { data } = await client.rest().actions.listSelfHostedRunnersForRepo({
          owner,
          repo,
          per_page: 100,
        });

        if (data.total_count > 0) {
          const runnerNames = data.runners.map(
            (r: any) => `${r.name} (${r.os}, status: ${r.status})`,
          );
          results.push({
            checkId: "ACT-005",
            title: "Self-hosted runners registered at repo level",
            severity: "HIGH",
            status: "FAIL",
            resource,
            category: "actions",
            details:
              `Repository '${resource}' has ${data.total_count} self-hosted runner(s) registered.\n` +
              `Runners:\n- ${runnerNames.join("\n- ")}`,
            remediation:
              "1. Use ephemeral runners (--ephemeral flag).\n" +
              "2. Avoid self-hosted runners on public repositories.\n" +
              "3. Use GitHub-hosted runners where possible.",
            reference:
              "https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/about-self-hosted-runners#self-hosted-runner-security",
          });
        }
      } catch (err: any) {
        if (err.status !== 404 && err.status !== 403) throw err;
        // Ignore permission errors for repo-level runner listing
      }

      // Check workflow files for self-hosted runner references
      const workflows = await getWorkflowFiles(client, owner, repo);
      const selfHostedWorkflows: string[] = [];

      for (const wf of workflows) {
        SELF_HOSTED_PATTERN.lastIndex = 0;
        if (SELF_HOSTED_PATTERN.test(wf.content)) {
          selfHostedWorkflows.push(wf.name);
        }
      }

      if (selfHostedWorkflows.length > 0) {
        results.push({
          checkId: "ACT-005",
          title: "Workflows use self-hosted runners",
          severity: "HIGH",
          status: "FAIL",
          resource,
          category: "actions",
          details:
            `${selfHostedWorkflows.length} workflow(s) reference 'self-hosted' in runs-on:\n` +
            `- ${selfHostedWorkflows.join("\n- ")}\n\n` +
            `Self-hosted runners persist state between workflow runs, creating risk of cross-job contamination.`,
          remediation:
            "Review whether self-hosted runners are necessary. If so, use ephemeral mode " +
            "and restrict which workflows can use them. Consider GitHub-hosted larger runners as an alternative.",
          reference:
            "https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/about-self-hosted-runners#self-hosted-runner-security",
        });
      }
    }

    // If no checks produced results, emit a PASS
    if (results.length === 0) {
      results.push({
        checkId: "ACT-005",
        title: "No self-hosted runner exposure detected",
        severity: "HIGH",
        status: "PASS",
        resource: org ? `org/${org}` : `${owner}/${repo}`,
        category: "actions",
        details: "No self-hosted runners found and no workflows reference self-hosted runners.",
        remediation: "No action needed.",
      });
    }
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    results.push({
      checkId: "ACT-005",
      title: "Self-hosted runner check failed",
      severity: "HIGH",
      status: "ERROR",
      resource: org ? `org/${org}` : `${owner}/${repo}`,
      category: "actions",
      details: `Failed to check self-hosted runners: ${message}`,
      remediation: "Ensure the token has appropriate scopes (repo, admin:org for org-level checks).",
    });
  }

  return results;
}
