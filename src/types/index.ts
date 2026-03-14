import type { z } from "zod";

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
export type CheckStatus = "PASS" | "FAIL" | "ERROR" | "NOT_APPLICABLE";
export type CheckCategory = "org" | "repo" | "actions" | "secrets" | "supply-chain" | "access";

export interface CheckResult {
  checkId: string;
  title: string;
  severity: Severity;
  status: CheckStatus;
  resource: string;
  category: CheckCategory;
  details: string;
  remediation: string;
  reference?: string;
}

export interface CheckMeta {
  id: string;
  category: CheckCategory;
  title: string;
  severity: Severity;
  description: string;
  references: string[];
}

export interface ToolDef {
  name: string;
  description: string;
  schema: Record<string, z.ZodType>;
  execute: (args: any, ctx: ToolContext) => Promise<ToolResult>;
}

export interface ToolContext {
  getClient: () => import("../github/client.js").GitHubClientFactory;
  getFindings: () => CheckResult[];
  addFindings: (results: CheckResult[]) => void;
  clearFindings: () => void;
}

export interface ToolResult {
  content: { type: "text"; text: string }[];
}
