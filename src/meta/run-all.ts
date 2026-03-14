import type { CheckResult, ToolContext } from "../types/index.js";

// Org check imports
import { checkOrgSecurity } from "../org/security.js";
import { checkOrgSso } from "../org/sso.js";
import { checkOrgMembers } from "../org/members.js";
import { checkOrgApps } from "../org/apps.js";
import { checkOrgWebhooks } from "../org/webhooks.js";
import { checkOrgAuditLog } from "../org/audit-log.js";

// Repo check imports
import { checkBranchProtection } from "../repo/branch-protection.js";
import { checkRepoSecretScanning } from "../repo/secret-scanning.js";
import { checkCodeScanning } from "../repo/code-scanning.js";
import { checkDependabot } from "../repo/dependabot.js";
import { checkRepoSettings } from "../repo/settings.js";
import { checkRepoWebhooks } from "../repo/webhooks.js";
import { checkDeployKeys } from "../repo/deploy-keys.js";
import { checkCodeowners } from "../repo/codeowners.js";

// Actions check imports
import { checkWorkflowInjection } from "../actions/injection.js";
import { checkPrTarget } from "../actions/pr-target.js";
import { checkWorkflowPermissions } from "../actions/permissions.js";
import { checkActionPinning } from "../actions/pinning.js";
import { checkRunners } from "../actions/runners.js";
import { checkEnvironments } from "../actions/environments.js";
import { checkWorkflowSecrets } from "../actions/secrets.js";
import { checkOidc } from "../actions/oidc.js";

// Secrets check imports
import { checkSecretScanning } from "../secrets/scanning.js";
import { checkPushProtection } from "../secrets/push-protection.js";
import { checkSecretPatterns } from "../secrets/patterns.js";
import { checkSecretScoping } from "../secrets/scoping.js";

// Supply chain check imports
import { checkDependencyGraph } from "../supply-chain/dependency-graph.js";
import { checkDependabotUpdates } from "../supply-chain/dependabot-updates.js";
import { checkSbom } from "../supply-chain/sbom.js";
import { checkVulnerabilities } from "../supply-chain/vulnerabilities.js";

// Access control check imports
import { checkTeamPermissions } from "../access/teams.js";
import { checkCollaborators } from "../access/collaborators.js";
import { checkAppPermissions } from "../access/github-apps.js";
import { checkTokenUsage } from "../access/tokens.js";

export async function runAll(
  ctx: ToolContext,
  args: { org?: string; owner?: string; repo?: string }
): Promise<CheckResult[]> {
  const results: CheckResult[] = [];
  const client = ctx.getClient();

  const org = (args.org || args.owner || "") as string;
  const owner = (args.owner || args.org || "") as string;
  const repo = (args.repo || "") as string;

  async function safeRun(fn: () => Promise<CheckResult[]>, label: string) {
    try {
      const r = await fn();
      results.push(...r);
    } catch (err) {
      console.error(`[github-security] ${label} error: ${(err as Error).message}`);
    }
  }

  // Organization checks (require org)
  if (org) {
    const orgArgs = { org } as Record<string, unknown>;
    await safeRun(() => checkOrgSecurity(client, orgArgs), "org-security");
    await safeRun(() => checkOrgSso(client, orgArgs), "org-sso");
    await safeRun(() => checkOrgMembers(client, orgArgs), "org-members");
    await safeRun(() => checkOrgApps(client, orgArgs), "org-apps");
    await safeRun(() => checkOrgWebhooks(client, orgArgs), "org-webhooks");
    await safeRun(() => checkOrgAuditLog(client, orgArgs), "org-audit-log");
  }

  // Repository checks (require owner + repo)
  if (owner && repo) {
    const repoArgs = { owner, repo } as Record<string, unknown>;
    await safeRun(() => checkBranchProtection(client, repoArgs), "repo-branch-protection");
    await safeRun(() => checkRepoSecretScanning(client, repoArgs), "repo-secret-scanning");
    await safeRun(() => checkCodeScanning(client, repoArgs), "repo-code-scanning");
    await safeRun(() => checkDependabot(client, repoArgs), "repo-dependabot");
    await safeRun(() => checkRepoSettings(client, repoArgs), "repo-settings");
    await safeRun(() => checkRepoWebhooks(client, repoArgs), "repo-webhooks");
    await safeRun(() => checkDeployKeys(client, repoArgs), "repo-deploy-keys");
    await safeRun(() => checkCodeowners(client, repoArgs), "repo-codeowners");

    // Actions checks
    await safeRun(() => checkWorkflowInjection(client, repoArgs), "actions-injection");
    await safeRun(() => checkPrTarget(client, repoArgs), "actions-pr-target");
    await safeRun(() => checkWorkflowPermissions(client, repoArgs), "actions-permissions");
    await safeRun(() => checkActionPinning(client, repoArgs), "actions-pinning");
    await safeRun(() => checkRunners(client, { ...repoArgs, org }), "actions-runners");
    await safeRun(() => checkEnvironments(client, repoArgs), "actions-environments");
    await safeRun(() => checkWorkflowSecrets(client, repoArgs), "actions-secrets");
    await safeRun(() => checkOidc(client, repoArgs), "actions-oidc");

    // Secrets checks
    await safeRun(() => checkSecretScanning(client, repoArgs), "secrets-scanning");
    await safeRun(() => checkPushProtection(client, repoArgs), "secrets-push-protection");
    await safeRun(() => checkSecretScoping(client, repoArgs), "secrets-scoping");

    // Supply chain checks
    await safeRun(() => checkDependencyGraph(client, repoArgs), "supply-chain-dep-graph");
    await safeRun(() => checkDependabotUpdates(client, repoArgs), "supply-chain-dependabot");
    await safeRun(() => checkSbom(client, repoArgs), "supply-chain-sbom");
    await safeRun(() => checkVulnerabilities(client, repoArgs), "supply-chain-vulns");

    // Access control checks
    await safeRun(() => checkTeamPermissions(client, { org, repo }), "access-teams");
    await safeRun(() => checkCollaborators(client, repoArgs), "access-collaborators");
    await safeRun(() => checkAppPermissions(client, repoArgs), "access-apps");
  }

  // Org-level checks that don't need a specific repo
  if (org) {
    const orgArgs = { org } as Record<string, unknown>;
    await safeRun(() => checkSecretPatterns(client, orgArgs), "secrets-patterns");
    await safeRun(() => checkTokenUsage(client, orgArgs), "access-tokens");
  }

  ctx.addFindings(results);
  return results;
}
