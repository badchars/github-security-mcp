import type { CheckResult } from "../types/index.js";
import type { GitHubClientFactory } from "../github/client.js";

/**
 * ORG-004: SAML SSO configuration check
 */
export async function checkOrgSso(
  client: GitHubClientFactory,
  args: Record<string, unknown>,
): Promise<CheckResult[]> {
  const org = args.org as string;
  const results: CheckResult[] = [];

  try {
    const gql = client.graphqlClient();
    const response = await gql<{
      organization: {
        samlIdentityProvider: { id: string; ssoUrl: string } | null;
      };
    }>(
      `
      query($org: String!) {
        organization(login: $org) {
          samlIdentityProvider {
            id
            ssoUrl
          }
        }
      }
      `,
      { org },
    );

    const saml = response.organization.samlIdentityProvider;

    results.push({
      checkId: "ORG-004",
      title: "SAML SSO not configured",
      severity: "HIGH",
      status: saml ? "PASS" : "FAIL",
      resource: `org/${org}`,
      category: "org",
      details: saml
        ? `Organization '${org}' has SAML SSO configured (provider URL: ${saml.ssoUrl}).`
        : `Organization '${org}' does not have SAML SSO configured. Without SSO, members authenticate only with GitHub credentials, lacking centralized identity management and session control.`,
      remediation:
        "Configure SAML SSO in Organization Settings > Authentication security > SAML single sign-on. This requires a GitHub Enterprise Cloud plan.",
      reference:
        "https://docs.github.com/en/organizations/managing-saml-single-sign-on-for-your-organization/about-identity-and-access-management-with-saml-single-sign-on",
    });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);

    // 403 means org is not on Enterprise plan (SAML requires Enterprise Cloud)
    const isNotEnterprise =
      message.includes("403") ||
      message.includes("404") ||
      message.includes("Not Found") ||
      message.includes("Could not resolve") ||
      message.includes("Must have admin rights") ||
      message.includes("SAML") ||
      message.includes("not available");

    results.push({
      checkId: "ORG-004",
      title: "SAML SSO not configured",
      severity: "HIGH",
      status: isNotEnterprise ? "NOT_APPLICABLE" : "ERROR",
      resource: `org/${org}`,
      category: "org",
      details: isNotEnterprise
        ? `SAML SSO check is not applicable for organization '${org}'. SAML SSO requires GitHub Enterprise Cloud.`
        : `Failed to check SAML SSO for organization '${org}': ${message}`,
      remediation: isNotEnterprise
        ? "Upgrade to GitHub Enterprise Cloud to enable SAML SSO."
        : "Verify the token has admin:org scope and the organization name is correct.",
      reference:
        "https://docs.github.com/en/organizations/managing-saml-single-sign-on-for-your-organization/about-identity-and-access-management-with-saml-single-sign-on",
    });
  }

  return results;
}
