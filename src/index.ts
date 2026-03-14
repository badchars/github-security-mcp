import { startMcpStdio } from "./protocol/mcp-server.js";
import { GitHubClientFactory } from "./github/client.js";
import type { ToolContext, CheckResult } from "./types/index.js";

// Global state
let findings: CheckResult[] = [];
let ghClient: GitHubClientFactory | null = null;

function buildToolContext(): ToolContext {
  return {
    getClient: () => {
      if (!ghClient) ghClient = new GitHubClientFactory();
      return ghClient;
    },
    getFindings: () => findings,
    addFindings: (results) => { findings.push(...results); },
    clearFindings: () => { findings = []; },
  };
}

async function main() {
  const args = process.argv.slice(2);

  if (args.includes("--help") || args.includes("-h")) {
    console.log(`github-security-mcp — GitHub security posture audit tools for AI agents

Usage:
  bun run src/index.ts [options]

Options:
  --help, -h  Show this help

Environment:
  GITHUB_TOKEN  GitHub Personal Access Token (classic or fine-grained)
`);
    return;
  }

  const ctx = buildToolContext();

  process.on("SIGINT", () => {
    console.error("[github-security] Shutting down...");
    process.exit(0);
  });

  console.error("[github-security] Starting MCP server (stdio)...");
  await startMcpStdio(ctx);
  await new Promise(() => {});
}

main();
