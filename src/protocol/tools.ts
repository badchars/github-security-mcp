/**
 * MCP Tool Definitions — 39 tools across 7 categories.
 *
 * Each tool is defined with Zod schema and an executor function.
 */

import { z } from "zod";
import type { ToolDef, ToolContext, ToolResult } from "../types/index.js";

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

// Meta imports
import { listChecks } from "../meta/list-checks.js";
import { auditSummary } from "../meta/summary.js";
import { auditReport } from "../meta/report.js";
import { runAll } from "../meta/run-all.js";

function text(msg: string): ToolResult {
  return { content: [{ type: "text", text: msg }] };
}

function json(data: unknown): ToolResult {
  return text(JSON.stringify(data, null, 2));
}

export const allTools: ToolDef[] = [
  // ═══ Organization Security (7 tools) ═══

  {
    name: "github_check_org_security",
    description: "Check organization security settings: 2FA enforcement, default repository visibility, member privileges. Detects ORG-001, ORG-002, ORG-003.",
    schema: {
      org: z.string().describe("GitHub organization name"),
    },
    execute: async (args, ctx) => {
      const results = await checkOrgSecurity(ctx.getClient(), args);
      ctx.addFindings(results);
      return json({ checkIds: ["ORG-001", "ORG-002", "ORG-003"], total: results.length, pass: results.filter(r => r.status === "PASS").length, fail: results.filter(r => r.status === "FAIL").length, findings: results });
    },
  },
  {
    name: "github_check_org_sso",
    description: "Check if SSO/SAML single sign-on is configured for the organization. Detects ORG-004.",
    schema: {
      org: z.string().describe("GitHub organization name"),
    },
    execute: async (args, ctx) => {
      const results = await checkOrgSso(ctx.getClient(), args);
      ctx.addFindings(results);
      return json({ checkIds: ["ORG-004"], total: results.length, findings: results });
    },
  },
  {
    name: "github_check_org_members",
    description: "Audit organization members: outside collaborators and member activity. Detects ORG-005, ORG-006.",
    schema: {
      org: z.string().describe("GitHub organization name"),
    },
    execute: async (args, ctx) => {
      const results = await checkOrgMembers(ctx.getClient(), args);
      ctx.addFindings(results);
      return json({ checkIds: ["ORG-005", "ORG-006"], total: results.length, findings: results });
    },
  },
  {
    name: "github_check_org_apps",
    description: "Audit OAuth app authorizations and GitHub App installations for the organization. Detects ORG-007, ORG-008.",
    schema: {
      org: z.string().describe("GitHub organization name"),
    },
    execute: async (args, ctx) => {
      const results = await checkOrgApps(ctx.getClient(), args);
      ctx.addFindings(results);
      return json({ checkIds: ["ORG-007", "ORG-008"], total: results.length, findings: results });
    },
  },
  {
    name: "github_check_org_webhooks",
    description: "Check organization webhooks for insecure HTTP URLs and SSL verification. Detects ORG-009.",
    schema: {
      org: z.string().describe("GitHub organization name"),
    },
    execute: async (args, ctx) => {
      const results = await checkOrgWebhooks(ctx.getClient(), args);
      ctx.addFindings(results);
      return json({ checkIds: ["ORG-009"], total: results.length, findings: results });
    },
  },
  {
    name: "github_check_org_audit_log",
    description: "Review organization audit log for suspicious or high-risk events. Detects ORG-010.",
    schema: {
      org: z.string().describe("GitHub organization name"),
    },
    execute: async (args, ctx) => {
      const results = await checkOrgAuditLog(ctx.getClient(), args);
      ctx.addFindings(results);
      return json({ checkIds: ["ORG-010"], total: results.length, findings: results });
    },
  },
  {
    name: "github_list_org_repos",
    description: "List organization repositories with security metadata (visibility, fork count, archived status). Useful for selecting repos to audit.",
    schema: {
      org: z.string().describe("GitHub organization name"),
      type: z.enum(["all", "public", "private", "forks", "sources"]).optional().describe("Repository type filter (default: all)"),
    },
    execute: async (args, ctx) => {
      const octokit = ctx.getClient().rest();
      const repos = await octokit.paginate(octokit.repos.listForOrg, {
        org: args.org as string,
        type: (args.type as any) || "all",
        per_page: 100,
      });
      const summary = repos.map(r => ({
        name: r.full_name,
        visibility: r.visibility || (r.private ? "private" : "public"),
        default_branch: r.default_branch,
        archived: r.archived,
        fork: r.fork,
        language: r.language,
        pushed_at: r.pushed_at,
      }));
      return json({ total: summary.length, repos: summary });
    },
  },

  // ═══ Repository Security (8 tools) ═══

  {
    name: "github_check_repo_branch_protection",
    description: "Check branch protection rules on the default branch: required reviews, status checks, admin enforcement, signed commits. Detects REPO-001.",
    schema: {
      owner: z.string().describe("Repository owner (user or org)"),
      repo: z.string().describe("Repository name"),
    },
    execute: async (args, ctx) => {
      const results = await checkBranchProtection(ctx.getClient(), args);
      ctx.addFindings(results);
      return json({ checkIds: ["REPO-001"], total: results.length, findings: results });
    },
  },
  {
    name: "github_check_repo_secrets",
    description: "Check if secret scanning and push protection are enabled for the repository. Detects REPO-002, REPO-003.",
    schema: {
      owner: z.string().describe("Repository owner"),
      repo: z.string().describe("Repository name"),
    },
    execute: async (args, ctx) => {
      const results = await checkRepoSecretScanning(ctx.getClient(), args);
      ctx.addFindings(results);
      return json({ checkIds: ["REPO-002", "REPO-003"], total: results.length, findings: results });
    },
  },
  {
    name: "github_check_repo_code_scanning",
    description: "Check if code scanning (CodeQL) is configured and review open alerts. Detects REPO-004, REPO-005.",
    schema: {
      owner: z.string().describe("Repository owner"),
      repo: z.string().describe("Repository name"),
    },
    execute: async (args, ctx) => {
      const results = await checkCodeScanning(ctx.getClient(), args);
      ctx.addFindings(results);
      return json({ checkIds: ["REPO-004", "REPO-005"], total: results.length, findings: results });
    },
  },
  {
    name: "github_check_repo_dependabot",
    description: "Check Dependabot configuration and open security alerts. Detects REPO-006, REPO-007.",
    schema: {
      owner: z.string().describe("Repository owner"),
      repo: z.string().describe("Repository name"),
    },
    execute: async (args, ctx) => {
      const results = await checkDependabot(ctx.getClient(), args);
      ctx.addFindings(results);
      return json({ checkIds: ["REPO-006", "REPO-007"], total: results.length, findings: results });
    },
  },
  {
    name: "github_check_repo_settings",
    description: "Check repository security settings: SECURITY.md, private vulnerability reporting, fork restrictions. Detects REPO-008, REPO-009, REPO-010.",
    schema: {
      owner: z.string().describe("Repository owner"),
      repo: z.string().describe("Repository name"),
    },
    execute: async (args, ctx) => {
      const results = await checkRepoSettings(ctx.getClient(), args);
      ctx.addFindings(results);
      return json({ checkIds: ["REPO-008", "REPO-009", "REPO-010"], total: results.length, findings: results });
    },
  },
  {
    name: "github_check_repo_webhooks",
    description: "Check repository webhooks for insecure HTTP URLs and SSL verification. Detects REPO-011.",
    schema: {
      owner: z.string().describe("Repository owner"),
      repo: z.string().describe("Repository name"),
    },
    execute: async (args, ctx) => {
      const results = await checkRepoWebhooks(ctx.getClient(), args);
      ctx.addFindings(results);
      return json({ checkIds: ["REPO-011"], total: results.length, findings: results });
    },
  },
  {
    name: "github_check_repo_deploy_keys",
    description: "Audit deploy keys for unnecessary write access. Detects REPO-012.",
    schema: {
      owner: z.string().describe("Repository owner"),
      repo: z.string().describe("Repository name"),
    },
    execute: async (args, ctx) => {
      const results = await checkDeployKeys(ctx.getClient(), args);
      ctx.addFindings(results);
      return json({ checkIds: ["REPO-012"], total: results.length, findings: results });
    },
  },
  {
    name: "github_check_repo_codeowners",
    description: "Check if CODEOWNERS file exists for code review enforcement. Detects REPO-013.",
    schema: {
      owner: z.string().describe("Repository owner"),
      repo: z.string().describe("Repository name"),
    },
    execute: async (args, ctx) => {
      const results = await checkCodeowners(ctx.getClient(), args);
      ctx.addFindings(results);
      return json({ checkIds: ["REPO-013"], total: results.length, findings: results });
    },
  },

  // ═══ GitHub Actions Security (8 tools) ═══

  {
    name: "github_check_workflow_injection",
    description: "Scan workflow files for script injection vulnerabilities via untrusted event inputs (${{ github.event.issue.title }}, etc. in run: blocks). Detects ACT-001.",
    schema: {
      owner: z.string().describe("Repository owner"),
      repo: z.string().describe("Repository name"),
    },
    execute: async (args, ctx) => {
      const results = await checkWorkflowInjection(ctx.getClient(), args);
      ctx.addFindings(results);
      return json({ checkIds: ["ACT-001"], total: results.length, findings: results });
    },
  },
  {
    name: "github_check_workflow_pr_target",
    description: "Detect dangerous pull_request_target + checkout pattern that enables arbitrary code execution from fork PRs. Detects ACT-002.",
    schema: {
      owner: z.string().describe("Repository owner"),
      repo: z.string().describe("Repository name"),
    },
    execute: async (args, ctx) => {
      const results = await checkPrTarget(ctx.getClient(), args);
      ctx.addFindings(results);
      return json({ checkIds: ["ACT-002"], total: results.length, findings: results });
    },
  },
  {
    name: "github_check_workflow_permissions",
    description: "Check GITHUB_TOKEN default permissions (should be read, not write). Detects ACT-003.",
    schema: {
      owner: z.string().describe("Repository owner"),
      repo: z.string().describe("Repository name"),
    },
    execute: async (args, ctx) => {
      const results = await checkWorkflowPermissions(ctx.getClient(), args);
      ctx.addFindings(results);
      return json({ checkIds: ["ACT-003"], total: results.length, findings: results });
    },
  },
  {
    name: "github_check_workflow_pinning",
    description: "Detect unpinned third-party actions (tag reference vs SHA pinning). Detects ACT-004.",
    schema: {
      owner: z.string().describe("Repository owner"),
      repo: z.string().describe("Repository name"),
    },
    execute: async (args, ctx) => {
      const results = await checkActionPinning(ctx.getClient(), args);
      ctx.addFindings(results);
      return json({ checkIds: ["ACT-004"], total: results.length, findings: results });
    },
  },
  {
    name: "github_check_workflow_runners",
    description: "Detect self-hosted runners and assess persistence/exposure risk. Detects ACT-005.",
    schema: {
      org: z.string().optional().describe("Organization name (for org-level runners)"),
      owner: z.string().optional().describe("Repository owner"),
      repo: z.string().optional().describe("Repository name"),
    },
    execute: async (args, ctx) => {
      const results = await checkRunners(ctx.getClient(), args);
      ctx.addFindings(results);
      return json({ checkIds: ["ACT-005"], total: results.length, findings: results });
    },
  },
  {
    name: "github_check_workflow_environments",
    description: "Check deployment environments for missing protection rules (reviewers, wait timers, branch policies). Detects ACT-006.",
    schema: {
      owner: z.string().describe("Repository owner"),
      repo: z.string().describe("Repository name"),
    },
    execute: async (args, ctx) => {
      const results = await checkEnvironments(ctx.getClient(), args);
      ctx.addFindings(results);
      return json({ checkIds: ["ACT-006"], total: results.length, findings: results });
    },
  },
  {
    name: "github_check_workflow_secrets",
    description: "Detect patterns where secrets are passed to network commands (curl/wget) or logged in workflow files. Detects ACT-007.",
    schema: {
      owner: z.string().describe("Repository owner"),
      repo: z.string().describe("Repository name"),
    },
    execute: async (args, ctx) => {
      const results = await checkWorkflowSecrets(ctx.getClient(), args);
      ctx.addFindings(results);
      return json({ checkIds: ["ACT-007"], total: results.length, findings: results });
    },
  },
  {
    name: "github_check_workflow_oidc",
    description: "Check OIDC subject claim customization for secure cloud deployment trust. Detects ACT-008.",
    schema: {
      owner: z.string().describe("Repository owner"),
      repo: z.string().describe("Repository name"),
    },
    execute: async (args, ctx) => {
      const results = await checkOidc(ctx.getClient(), args);
      ctx.addFindings(results);
      return json({ checkIds: ["ACT-008"], total: results.length, findings: results });
    },
  },

  // ═══ Secrets & Credentials (4 tools) ═══

  {
    name: "github_check_secret_scanning",
    description: "Check secret scanning coverage and review open alerts. Detects SEC-001, SEC-002.",
    schema: {
      owner: z.string().describe("Repository owner"),
      repo: z.string().describe("Repository name"),
    },
    execute: async (args, ctx) => {
      const results = await checkSecretScanning(ctx.getClient(), args);
      ctx.addFindings(results);
      return json({ checkIds: ["SEC-001", "SEC-002"], total: results.length, findings: results });
    },
  },
  {
    name: "github_check_push_protection",
    description: "Check for secret scanning alerts where push protection was bypassed. Detects SEC-003.",
    schema: {
      owner: z.string().describe("Repository owner"),
      repo: z.string().describe("Repository name"),
    },
    execute: async (args, ctx) => {
      const results = await checkPushProtection(ctx.getClient(), args);
      ctx.addFindings(results);
      return json({ checkIds: ["SEC-003"], total: results.length, findings: results });
    },
  },
  {
    name: "github_check_secret_patterns",
    description: "Check if organization has defined custom secret scanning patterns. Detects SEC-004.",
    schema: {
      org: z.string().describe("GitHub organization name"),
    },
    execute: async (args, ctx) => {
      const results = await checkSecretPatterns(ctx.getClient(), args);
      ctx.addFindings(results);
      return json({ checkIds: ["SEC-004"], total: results.length, findings: results });
    },
  },
  {
    name: "github_check_secret_scoping",
    description: "Review secret scoping across environments, repositories, and organization levels. Detects SEC-005.",
    schema: {
      owner: z.string().describe("Repository owner"),
      repo: z.string().describe("Repository name"),
    },
    execute: async (args, ctx) => {
      const results = await checkSecretScoping(ctx.getClient(), args);
      ctx.addFindings(results);
      return json({ checkIds: ["SEC-005"], total: results.length, findings: results });
    },
  },

  // ═══ Supply Chain (4 tools) ═══

  {
    name: "github_check_dependency_graph",
    description: "Check if the dependency graph is enabled for vulnerability detection. Detects SUP-001.",
    schema: {
      owner: z.string().describe("Repository owner"),
      repo: z.string().describe("Repository name"),
    },
    execute: async (args, ctx) => {
      const results = await checkDependencyGraph(ctx.getClient(), args);
      ctx.addFindings(results);
      return json({ checkIds: ["SUP-001"], total: results.length, findings: results });
    },
  },
  {
    name: "github_check_dependabot_updates",
    description: "Check if Dependabot security updates and version updates are configured. Detects SUP-002.",
    schema: {
      owner: z.string().describe("Repository owner"),
      repo: z.string().describe("Repository name"),
    },
    execute: async (args, ctx) => {
      const results = await checkDependabotUpdates(ctx.getClient(), args);
      ctx.addFindings(results);
      return json({ checkIds: ["SUP-002"], total: results.length, findings: results });
    },
  },
  {
    name: "github_check_sbom",
    description: "Check if software bill of materials (SBOM) can be generated from the dependency graph. Detects SUP-003.",
    schema: {
      owner: z.string().describe("Repository owner"),
      repo: z.string().describe("Repository name"),
    },
    execute: async (args, ctx) => {
      const results = await checkSbom(ctx.getClient(), args);
      ctx.addFindings(results);
      return json({ checkIds: ["SUP-003"], total: results.length, findings: results });
    },
  },
  {
    name: "github_check_vulnerabilities",
    description: "Check for critical known vulnerabilities and stale unfixed alerts (>90 days). Detects SUP-004, SUP-005.",
    schema: {
      owner: z.string().describe("Repository owner"),
      repo: z.string().describe("Repository name"),
    },
    execute: async (args, ctx) => {
      const results = await checkVulnerabilities(ctx.getClient(), args);
      ctx.addFindings(results);
      return json({ checkIds: ["SUP-004", "SUP-005"], total: results.length, findings: results });
    },
  },

  // ═══ Access Control (4 tools) ═══

  {
    name: "github_check_team_permissions",
    description: "Audit team permissions for admin-level access to repositories. Detects ACC-001.",
    schema: {
      org: z.string().describe("GitHub organization name"),
      repo: z.string().optional().describe("Specific repository name (default: org-wide audit)"),
    },
    execute: async (args, ctx) => {
      const results = await checkTeamPermissions(ctx.getClient(), args);
      ctx.addFindings(results);
      return json({ checkIds: ["ACC-001"], total: results.length, findings: results });
    },
  },
  {
    name: "github_check_collaborators",
    description: "Check for outside collaborators with write, maintain, or admin permissions. Detects ACC-002.",
    schema: {
      owner: z.string().describe("Repository owner"),
      repo: z.string().describe("Repository name"),
    },
    execute: async (args, ctx) => {
      const results = await checkCollaborators(ctx.getClient(), args);
      ctx.addFindings(results);
      return json({ checkIds: ["ACC-002"], total: results.length, findings: results });
    },
  },
  {
    name: "github_check_app_permissions",
    description: "Audit GitHub App installations for overly broad permission scopes. Detects ACC-003.",
    schema: {
      owner: z.string().describe("Repository owner"),
      repo: z.string().describe("Repository name"),
    },
    execute: async (args, ctx) => {
      const results = await checkAppPermissions(ctx.getClient(), args);
      ctx.addFindings(results);
      return json({ checkIds: ["ACC-003"], total: results.length, findings: results });
    },
  },
  {
    name: "github_check_pat_usage",
    description: "Check for classic personal access tokens with overly broad scopes. Detects ACC-004.",
    schema: {
      org: z.string().describe("GitHub organization name"),
    },
    execute: async (args, ctx) => {
      const results = await checkTokenUsage(ctx.getClient(), args);
      ctx.addFindings(results);
      return json({ checkIds: ["ACC-004"], total: results.length, findings: results });
    },
  },

  // ═══ Meta (4 tools) ═══

  {
    name: "github_list_checks",
    description: "List all available security checks with their IDs, categories, severities, and descriptions. Filterable by category and severity.",
    schema: {
      category: z.string().optional().describe("Filter by category: org, repo, actions, secrets, supply-chain, access"),
      severity: z.string().optional().describe("Filter by severity: CRITICAL, HIGH, MEDIUM, LOW, INFO"),
    },
    execute: async (args) => {
      const checks = listChecks(args);
      return json({ total: checks.length, checks });
    },
  },
  {
    name: "github_audit_summary",
    description: "Aggregate all findings from the current session by category, severity, and status. Shows critical findings and top remediation actions.",
    schema: {},
    execute: async (_args, ctx) => {
      const summary = auditSummary(ctx.getFindings());
      return json(summary);
    },
  },
  {
    name: "github_audit_report",
    description: "Generate a comprehensive markdown security report from all findings in the current session.",
    schema: {
      title: z.string().optional().describe("Report title (default: GitHub Security Audit Report)"),
      format: z.enum(["markdown", "json"]).optional().describe("Output format (default: markdown)"),
      severityFilter: z.array(z.string()).optional().describe("Filter by severities, e.g. ['CRITICAL', 'HIGH']"),
    },
    execute: async (args, ctx) => {
      const report = auditReport(ctx.getFindings(), args);
      return text(report);
    },
  },
  {
    name: "github_run_all",
    description: "Run all security checks for an organization and/or repository. Executes org, repo, actions, secrets, supply chain, and access control checks sequentially.",
    schema: {
      org: z.string().optional().describe("GitHub organization name (for org-level checks)"),
      owner: z.string().optional().describe("Repository owner (defaults to org if not specified)"),
      repo: z.string().optional().describe("Repository name (for repo-level checks)"),
    },
    execute: async (args, ctx) => {
      const results = await runAll(ctx, args);
      const summary = auditSummary(results);
      return json({ total: results.length, byStatus: summary.byStatus, bySeverity: summary.bySeverity, byCategory: summary.byCategory });
    },
  },
];
