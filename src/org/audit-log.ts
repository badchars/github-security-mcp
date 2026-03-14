import type { CheckResult } from "../types/index.js";
import type { GitHubClientFactory } from "../github/client.js";

/**
 * ORG-010: Suspicious audit log activity detection
 */
export async function checkOrgAuditLog(
  client: GitHubClientFactory,
  args: Record<string, unknown>,
): Promise<CheckResult[]> {
  const org = args.org as string;
  const results: CheckResult[] = [];

  const highRiskActions = [
    "org.remove_member",
    "member.remove",
    "repo.destroy",
    "repo.delete",
    "team.remove_member",
    "org.update_member_repository_creation_permission",
    "org.disable_two_factor_requirement",
    "org.update_default_repository_permission",
    "protected_branch.destroy",
    "org.invite_member",
    "org.update_saml_provider",
  ];

  try {
    const { data: entries } = await client.rest().request(
      "GET /orgs/{org}/audit-log",
      { org, per_page: 50, include: "all" },
    );

    if (!Array.isArray(entries)) {
      results.push({
        checkId: "ORG-010",
        title: "Suspicious audit log activity",
        severity: "INFO",
        status: "NOT_APPLICABLE",
        resource: `org/${org}`,
        category: "org",
        details: `Audit log API returned unexpected format for organization '${org}'. This feature may require GitHub Enterprise.`,
        remediation:
          "Audit log API requires GitHub Enterprise Cloud. Upgrade if centralized audit logging is needed.",
      });
      return results;
    }

    const suspicious = entries.filter((entry: any) => {
      const action = entry.action ?? "";
      return highRiskActions.some(
        (risk) => action === risk || action.startsWith(risk),
      );
    });

    const summary = suspicious.slice(0, 10).map((entry: any) => {
      const action = entry.action ?? "unknown";
      const actor = entry.actor ?? "unknown";
      const createdAt = entry.created_at
        ? new Date(entry.created_at * 1000).toISOString()
        : entry["@timestamp"] ?? "unknown time";
      return `${action} by ${actor} at ${createdAt}`;
    });

    results.push({
      checkId: "ORG-010",
      title: "Suspicious audit log activity",
      severity: "INFO",
      status: suspicious.length > 0 ? "FAIL" : "PASS",
      resource: `org/${org}`,
      category: "org",
      details:
        suspicious.length > 0
          ? `Found ${suspicious.length} high-risk event(s) in recent audit log for '${org}'. ${summary.length <= 10 ? `Events: ${summary.join("; ")}` : `First 10: ${summary.join("; ")} (and ${suspicious.length - 10} more)`}`
          : `No high-risk events found in the last 50 audit log entries for '${org}'.`,
      remediation:
        "Review flagged audit log events. Investigate member removals, repository deletions, and permission changes. Set up audit log streaming for real-time alerting.",
      reference:
        "https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/reviewing-the-audit-log-for-your-organization",
    });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    const isNotAvailable =
      message.includes("404") || message.includes("Not Found");

    results.push({
      checkId: "ORG-010",
      title: "Suspicious audit log activity",
      severity: "INFO",
      status: isNotAvailable ? "NOT_APPLICABLE" : "ERROR",
      resource: `org/${org}`,
      category: "org",
      details: isNotAvailable
        ? `Audit log API is not available for organization '${org}'. This feature requires GitHub Enterprise Cloud.`
        : `Failed to retrieve audit log for '${org}': ${message}`,
      remediation: isNotAvailable
        ? "Upgrade to GitHub Enterprise Cloud to access the audit log API."
        : "Verify the token has admin:org scope and the organization name is correct.",
      reference:
        "https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/reviewing-the-audit-log-for-your-organization",
    });
  }

  return results;
}
