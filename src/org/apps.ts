import type { CheckResult } from "../types/index.js";
import type { GitHubClientFactory } from "../github/client.js";

/**
 * ORG-007: Risky OAuth app credential authorizations
 * ORG-008: Over-permissive GitHub App installations
 */
export async function checkOrgApps(
  client: GitHubClientFactory,
  args: Record<string, unknown>,
): Promise<CheckResult[]> {
  const org = args.org as string;
  const results: CheckResult[] = [];

  // ORG-007: OAuth app credential authorizations (Enterprise only)
  try {
    const { data: creds } = await client
      .rest()
      .request("GET /orgs/{org}/credential-authorizations", { org, per_page: 100 });

    const count = creds.length;
    const oauthApps = creds.filter(
      (c: any) => c.credential_type === "personal access token" || c.credential_type === "OAuth app token",
    );

    results.push({
      checkId: "ORG-007",
      title: "Risky OAuth app authorizations",
      severity: "HIGH",
      status: oauthApps.length > 0 ? "FAIL" : "PASS",
      resource: `org/${org}`,
      category: "org",
      details:
        oauthApps.length > 0
          ? `Organization '${org}' has ${count} credential authorization(s), including ${oauthApps.length} OAuth/PAT authorization(s). These tokens may have broad access to organization resources. Review each authorization to ensure it is still needed.`
          : `Organization '${org}' has ${count} credential authorization(s). No OAuth/PAT authorizations found.`,
      remediation:
        "Review credential authorizations in Organization Settings > Third-party access > Credential authorizations. Revoke any that are no longer needed.",
      reference:
        "https://docs.github.com/en/organizations/granting-access-to-your-organization-with-saml-single-sign-on/viewing-and-managing-a-members-saml-access-to-your-organization",
    });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    const isNotEnterprise =
      message.includes("404") || message.includes("Not Found");

    results.push({
      checkId: "ORG-007",
      title: "Risky OAuth app authorizations",
      severity: "HIGH",
      status: isNotEnterprise ? "NOT_APPLICABLE" : "ERROR",
      resource: `org/${org}`,
      category: "org",
      details: isNotEnterprise
        ? `Credential authorization listing is not available for organization '${org}'. This feature requires GitHub Enterprise Cloud with SAML SSO enabled.`
        : `Failed to list credential authorizations for '${org}': ${message}`,
      remediation: isNotEnterprise
        ? "This check requires GitHub Enterprise Cloud with SAML SSO configured."
        : "Verify the token has admin:org scope and the organization name is correct.",
    });
  }

  // ORG-008: Over-permissive GitHub App installations
  try {
    const { data } = await client
      .rest()
      .orgs.listAppInstallations({ org, per_page: 100 });

    const installations = data.installations ?? data;
    const overPermissive: string[] = [];
    const highRiskPerms = [
      "administration",
      "organization_administration",
      "members",
      "organization_hooks",
      "organization_secrets",
    ];

    for (const install of installations as any[]) {
      const perms = install.permissions ?? {};
      const riskyPerms = Object.entries(perms).filter(
        ([key, value]) =>
          (value === "admin" || value === "write") &&
          highRiskPerms.includes(key),
      );

      const hasAllRepos = install.repository_selection === "all";

      if (riskyPerms.length > 0 || hasAllRepos) {
        const appName = install.app_slug ?? install.app_id ?? "unknown";
        const reasons: string[] = [];
        if (hasAllRepos) reasons.push("access to ALL repositories");
        if (riskyPerms.length > 0)
          reasons.push(
            `high-risk permissions: ${riskyPerms.map(([k, v]) => `${k}:${v}`).join(", ")}`,
          );
        overPermissive.push(`${appName} (${reasons.join("; ")})`);
      }
    }

    const totalCount = (installations as any[]).length;

    results.push({
      checkId: "ORG-008",
      title: "Over-permissive GitHub App installations",
      severity: "HIGH",
      status: overPermissive.length > 0 ? "FAIL" : "PASS",
      resource: `org/${org}`,
      category: "org",
      details:
        overPermissive.length > 0
          ? `Organization '${org}' has ${totalCount} GitHub App installation(s), ${overPermissive.length} with excessive permissions: ${overPermissive.join("; ")}.`
          : `Organization '${org}' has ${totalCount} GitHub App installation(s). None have overly broad permissions.`,
      remediation:
        "Review GitHub App installations in Organization Settings > Third-party access > GitHub Apps. Restrict repository access to specific repos and reduce permission scopes.",
      reference:
        "https://docs.github.com/en/organizations/managing-programmatic-access-to-your-organization/reviewing-and-revoking-personal-access-tokens-in-your-organization",
    });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    const isNotOrg = message.includes("404") || message.includes("Not Found");
    results.push({
      checkId: "ORG-008",
      title: "Over-permissive GitHub App installations",
      severity: "HIGH",
      status: isNotOrg ? "NOT_APPLICABLE" : "ERROR",
      resource: `org/${org}`,
      category: "org",
      details: isNotOrg
        ? `'${org}' is not an organization or does not exist.`
        : `Failed to list GitHub App installations for '${org}': ${message}`,
      remediation: isNotOrg
        ? "Provide a valid GitHub organization name."
        : "Verify the token has admin:org scope and the organization name is correct.",
    });
  }

  return results;
}
