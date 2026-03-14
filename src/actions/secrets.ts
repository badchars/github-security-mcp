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
 * Patterns that indicate potential secret exfiltration or unsafe secret handling.
 * Each pattern has a description and regex to match against run block contents.
 */
const SECRET_ABUSE_PATTERNS: Array<{ name: string; pattern: RegExp; description: string }> = [
  {
    name: "Secret in curl/wget URL or argument",
    pattern: /(?:curl|wget)\s+[^\n]*\$\{\{\s*secrets\./gi,
    description: "Secret value passed to curl/wget, potentially exfiltrating to an external server",
  },
  {
    name: "Secret echoed to stdout",
    pattern: /echo\s+[^\n]*\$\{\{\s*secrets\./gi,
    description: "Secret value printed to stdout via echo, exposing it in workflow logs",
  },
  {
    name: "Secret in URL parameter",
    pattern: /https?:\/\/[^\s]*\$\{\{\s*secrets\./gi,
    description: "Secret value interpolated into a URL, risking exposure in logs and server access logs",
  },
  {
    name: "Secret piped or redirected",
    pattern: /\$\{\{\s*secrets\.[^}]+\}\}\s*[|>]/gi,
    description: "Secret value piped or redirected, potentially written to a file or external command",
  },
  {
    name: "Secret in base64 encode/decode",
    pattern: /base64[^\n]*\$\{\{\s*secrets\./gi,
    description: "Secret processed through base64 encoding, common obfuscation technique for exfiltration",
  },
];

/**
 * ACT-007: Secret exfiltration patterns in workflows.
 *
 * Scans workflow YAML files for patterns where GitHub secrets are passed to network commands
 * (curl, wget), logged to stdout (echo), or otherwise handled in ways that could lead to
 * secret exfiltration. While GitHub masks secrets in logs, not all exfiltration vectors are
 * caught (e.g., base64-encoded values, URL parameters).
 */
export async function checkWorkflowSecrets(
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
        checkId: "ACT-007",
        title: "Secret exfiltration patterns in workflows",
        severity: "HIGH",
        status: "NOT_APPLICABLE",
        resource,
        category: "actions",
        details: "No workflow files found in .github/workflows/.",
        remediation: "No action needed — no workflows to audit.",
      });
      return results;
    }

    let hasSuspicious = false;

    for (const wf of workflows) {
      const findings: string[] = [];

      for (const { name, pattern, description } of SECRET_ABUSE_PATTERNS) {
        pattern.lastIndex = 0;
        const matches: string[] = [];
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(wf.content)) !== null) {
          // Truncate match for readability
          const snippet = match[0].length > 120 ? match[0].slice(0, 120) + "..." : match[0];
          matches.push(snippet.trim());
        }
        if (matches.length > 0) {
          findings.push(`${name} (${description}):\n    ${matches.join("\n    ")}`);
        }
      }

      if (findings.length > 0) {
        hasSuspicious = true;
        results.push({
          checkId: "ACT-007",
          title: "Suspicious secret usage in workflow",
          severity: "HIGH",
          status: "FAIL",
          resource: `${resource}/.github/workflows/${wf.name}`,
          category: "actions",
          details:
            `Workflow '${wf.name}' contains patterns that may exfiltrate or expose secrets:\n\n` +
            findings.join("\n\n"),
          remediation:
            "1. Never pass secrets directly in URLs or as curl/wget arguments.\n" +
            "2. Use environment variables instead of inline interpolation:\n" +
            "   ```yaml\n   env:\n     MY_TOKEN: ${{ secrets.TOKEN }}\n   run: curl -H \"Authorization: Bearer $MY_TOKEN\" ...\n   ```\n" +
            "3. Avoid echoing secrets — GitHub masks them, but encoded forms bypass masking.\n" +
            "4. Review third-party actions for secret handling before passing secrets via `with:`.",
          reference:
            "https://docs.github.com/en/actions/security-for-github-actions/security-guides/using-secrets-in-github-actions",
        });
      }
    }

    if (!hasSuspicious) {
      results.push({
        checkId: "ACT-007",
        title: "No suspicious secret usage patterns found",
        severity: "HIGH",
        status: "PASS",
        resource,
        category: "actions",
        details: `Scanned ${workflows.length} workflow file(s) — no secret exfiltration patterns detected.`,
        remediation: "No action needed.",
      });
    }
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    results.push({
      checkId: "ACT-007",
      title: "Secret exfiltration patterns check failed",
      severity: "HIGH",
      status: "ERROR",
      resource,
      category: "actions",
      details: `Failed to check workflow secrets for '${resource}': ${message}`,
      remediation: "Ensure the token has repo/contents:read scope and the repository exists.",
    });
  }

  return results;
}
