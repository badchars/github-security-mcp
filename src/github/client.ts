import { Octokit } from "@octokit/rest";
import { graphql } from "@octokit/graphql";

export class GitHubClientFactory {
  private octokit: Octokit | null = null;
  private gql: typeof graphql | null = null;
  private token: string;

  constructor() {
    this.token = process.env.GITHUB_TOKEN ?? "";
    if (!this.token) {
      console.error("[github-security] Warning: GITHUB_TOKEN not set. API calls will fail or be severely rate-limited.");
    }
  }

  rest(): Octokit {
    if (!this.octokit) {
      this.octokit = new Octokit({ auth: this.token || undefined });
    }
    return this.octokit;
  }

  graphqlClient(): typeof graphql {
    if (!this.gql) {
      this.gql = graphql.defaults({
        headers: this.token ? { authorization: `token ${this.token}` } : {},
      });
    }
    return this.gql;
  }

  async getIdentity(): Promise<{ login: string; type: string } | null> {
    try {
      const { data } = await this.rest().users.getAuthenticated();
      return { login: data.login, type: data.type };
    } catch {
      return null;
    }
  }

  hasToken(): boolean {
    return this.token.length > 0;
  }
}
