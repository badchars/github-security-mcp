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
 * Extract `run:` block contents from a workflow YAML string.
 * Returns an array of { lineNum, text } for each run block value.
 */
function extractRunBlocks(content: string): Array<{ lineNum: number; text: string }> {
  const lines = content.split("\n");
  const blocks: Array<{ lineNum: number; text: string }> = [];
  for (let i = 0; i < lines.length; i++) {
    const trimmed = lines[i].trimStart();
    if (/^run:\s*/i.test(trimmed)) {
      const runValue = trimmed.replace(/^run:\s*/i, "");
      if (runValue === "|" || runValue === "|+" || runValue === "|-" || runValue === ">") {
        // Multi-line run block — collect indented lines
        const baseIndent = lines[i].length - lines[i].trimStart().length;
        let multiline = "";
        let j = i + 1;
        while (j < lines.length) {
          const lineIndent = lines[j].length - lines[j].trimStart().length;
          if (lines[j].trim() === "" || lineIndent > baseIndent) {
            multiline += lines[j] + "\n";
            j++;
          } else {
            break;
          }
        }
        blocks.push({ lineNum: i + 1, text: multiline });
      } else {
        blocks.push({ lineNum: i + 1, text: runValue });
      }
    }
  }
  return blocks;
}

const DANGEROUS_PATTERN =
  /\$\{\{\s*github\.(event\.(issue\.(title|body)|pull_request\.(title|body|head\.ref)|comment\.body|review\.body|discussion\.(title|body)|pages.*\.page_name)|head_ref)/gi;

/**
 * ACT-001: Script injection via untrusted inputs in GitHub Actions workflow run blocks.
 *
 * Detects dangerous interpolations like ${{ github.event.issue.title }} inside `run:` blocks
 * that allow an attacker to inject arbitrary shell commands via PR titles, issue bodies, etc.
 */
export async function checkWorkflowInjection(
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
        checkId: "ACT-001",
        title: "Script injection via untrusted inputs",
        severity: "CRITICAL",
        status: "NOT_APPLICABLE",
        resource,
        category: "actions",
        details: "No workflow files found in .github/workflows/.",
        remediation: "No action needed — no workflows to audit.",
      });
      return results;
    }

    let hasInjection = false;

    for (const wf of workflows) {
      const runBlocks = extractRunBlocks(wf.content);
      const found: string[] = [];

      for (const block of runBlocks) {
        let match: RegExpExecArray | null;
        DANGEROUS_PATTERN.lastIndex = 0;
        while ((match = DANGEROUS_PATTERN.exec(block.text)) !== null) {
          found.push(`Line ~${block.lineNum}: ${match[0]}`);
        }
      }

      if (found.length > 0) {
        hasInjection = true;
        results.push({
          checkId: "ACT-001",
          title: "Script injection via untrusted inputs",
          severity: "CRITICAL",
          status: "FAIL",
          resource: `${resource}/.github/workflows/${wf.name}`,
          category: "actions",
          details: `Workflow '${wf.name}' contains dangerous expression interpolations in run blocks that can be exploited for arbitrary command execution:\n- ${found.join("\n- ")}`,
          remediation:
            "Never use untrusted event data directly in `run:` blocks. Instead, pass the value through an environment variable:\n\n" +
            "```yaml\nenv:\n  TITLE: ${{ github.event.issue.title }}\nrun: echo \"$TITLE\"\n```\n\n" +
            "This prevents shell metacharacter injection.",
          reference: "https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections",
        });
      }
    }

    if (!hasInjection) {
      results.push({
        checkId: "ACT-001",
        title: "Script injection via untrusted inputs",
        severity: "CRITICAL",
        status: "PASS",
        resource,
        category: "actions",
        details: `Scanned ${workflows.length} workflow file(s) — no dangerous expression interpolations found in run blocks.`,
        remediation: "No action needed.",
      });
    }
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    results.push({
      checkId: "ACT-001",
      title: "Script injection via untrusted inputs",
      severity: "CRITICAL",
      status: "ERROR",
      resource,
      category: "actions",
      details: `Failed to check workflow injection for '${resource}': ${message}`,
      remediation: "Ensure the token has repo/contents:read scope and the repository exists.",
    });
  }

  return results;
}
