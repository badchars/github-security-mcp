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

const PR_TARGET_TRIGGER = /pull_request_target/;
const CHECKOUT_PR_HEAD =
  /uses:\s+actions\/checkout[\s\S]*?ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.(sha|ref)\s*\}\}/gi;

/**
 * ACT-002: pull_request_target with checkout of PR head.
 *
 * The pull_request_target trigger runs in the context of the base repo (with secrets & write token).
 * If the workflow checks out the PR head ref, code from a forked PR runs with full repo privileges,
 * leading to arbitrary code execution, secret exfiltration, and supply chain compromise.
 */
export async function checkPrTarget(
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
        checkId: "ACT-002",
        title: "pull_request_target with checkout of PR head",
        severity: "CRITICAL",
        status: "NOT_APPLICABLE",
        resource,
        category: "actions",
        details: "No workflow files found in .github/workflows/.",
        remediation: "No action needed — no workflows to audit.",
      });
      return results;
    }

    let hasDangerousPattern = false;

    for (const wf of workflows) {
      if (!PR_TARGET_TRIGGER.test(wf.content)) continue;

      // Reset lastIndex for global regex
      CHECKOUT_PR_HEAD.lastIndex = 0;
      const matches: string[] = [];
      let match: RegExpExecArray | null;
      while ((match = CHECKOUT_PR_HEAD.exec(wf.content)) !== null) {
        matches.push(match[0].trim());
      }

      if (matches.length > 0) {
        hasDangerousPattern = true;
        results.push({
          checkId: "ACT-002",
          title: "pull_request_target with checkout of PR head",
          severity: "CRITICAL",
          status: "FAIL",
          resource: `${resource}/.github/workflows/${wf.name}`,
          category: "actions",
          details:
            `Workflow '${wf.name}' uses 'pull_request_target' trigger AND checks out the PR head ref. ` +
            `This allows a forked PR to execute arbitrary code with the base repo's secrets and write permissions.\n` +
            `Dangerous checkout patterns found:\n- ${matches.join("\n- ")}`,
          remediation:
            "Option 1: Use `pull_request` trigger instead (runs in fork context without secrets).\n" +
            "Option 2: If you must use `pull_request_target`, never checkout the PR head. " +
            "Use a two-workflow pattern: first workflow labels/approves, second runs code.\n" +
            "Option 3: If checkout is needed, only read files (no `npm install`, `make`, etc.) and use a read-only token.",
          reference:
            "https://securitylab.github.com/research/github-actions-preventing-pwn-requests/",
        });
      } else {
        // pull_request_target is used but without dangerous checkout — safe usage
        results.push({
          checkId: "ACT-002",
          title: "pull_request_target used safely",
          severity: "CRITICAL",
          status: "PASS",
          resource: `${resource}/.github/workflows/${wf.name}`,
          category: "actions",
          details: `Workflow '${wf.name}' uses 'pull_request_target' but does not check out the PR head ref.`,
          remediation: "No action needed.",
          reference:
            "https://securitylab.github.com/research/github-actions-preventing-pwn-requests/",
        });
      }
    }

    if (!hasDangerousPattern && results.length === 0) {
      results.push({
        checkId: "ACT-002",
        title: "pull_request_target with checkout of PR head",
        severity: "CRITICAL",
        status: "PASS",
        resource,
        category: "actions",
        details: `Scanned ${workflows.length} workflow file(s) — no pull_request_target triggers found.`,
        remediation: "No action needed.",
      });
    }
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    results.push({
      checkId: "ACT-002",
      title: "pull_request_target with checkout of PR head",
      severity: "CRITICAL",
      status: "ERROR",
      resource,
      category: "actions",
      details: `Failed to check pull_request_target patterns for '${resource}': ${message}`,
      remediation: "Ensure the token has repo/contents:read scope and the repository exists.",
    });
  }

  return results;
}
