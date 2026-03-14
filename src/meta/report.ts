import type { CheckResult } from "../types/index.js";
import { auditSummary } from "./summary.js";

export function auditReport(
  findings: CheckResult[],
  args: { title?: string; format?: string; severityFilter?: string[] }
): string {
  let filtered = findings;
  if (args.severityFilter && args.severityFilter.length > 0) {
    const allowed = new Set(args.severityFilter.map(s => s.toUpperCase()));
    filtered = findings.filter(f => allowed.has(f.severity));
  }

  if (args.format === "json") {
    return JSON.stringify({ title: args.title || "GitHub Security Audit Report", findings: filtered }, null, 2);
  }

  const summary = auditSummary(filtered);
  const title = args.title || "GitHub Security Audit Report";

  const lines: string[] = [
    `# ${title}`,
    "",
    `**Date:** ${new Date().toISOString().split("T")[0]}`,
    `**Total Findings:** ${summary.totalFindings}`,
    "",
    "## Summary",
    "",
    "| Status | Count |",
    "|--------|-------|",
    `| PASS | ${summary.byStatus.pass} |`,
    `| FAIL | ${summary.byStatus.fail} |`,
    `| ERROR | ${summary.byStatus.error} |`,
    "",
  ];

  // Category breakdown
  if (Object.keys(summary.byCategory).length > 0) {
    lines.push("## By Category", "", "| Category | Pass | Fail | Error |", "|----------|------|------|-------|");
    for (const [cat, counts] of Object.entries(summary.byCategory)) {
      lines.push(`| ${cat} | ${counts.pass} | ${counts.fail} | ${counts.error} |`);
    }
    lines.push("");
  }

  // Severity breakdown
  if (Object.keys(summary.bySeverity).length > 0) {
    lines.push("## Failures by Severity", "", "| Severity | Count |", "|----------|-------|");
    for (const sev of ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]) {
      if (summary.bySeverity[sev]) {
        lines.push(`| ${sev} | ${summary.bySeverity[sev]} |`);
      }
    }
    lines.push("");
  }

  // Critical findings
  const criticals = filtered.filter(f => f.status === "FAIL" && f.severity === "CRITICAL");
  if (criticals.length > 0) {
    lines.push("## Critical Findings", "");
    for (const f of criticals) {
      lines.push(
        `### ${f.checkId}: ${f.title}`,
        "",
        `- **Resource:** ${f.resource}`,
        `- **Category:** ${f.category}`,
        `- **Details:** ${f.details}`,
        `- **Remediation:** \`${f.remediation}\``,
        f.reference ? `- **Reference:** ${f.reference}` : "",
        ""
      );
    }
  }

  // High findings
  const highs = filtered.filter(f => f.status === "FAIL" && f.severity === "HIGH");
  if (highs.length > 0) {
    lines.push("## High Findings", "");
    for (const f of highs) {
      lines.push(
        `### ${f.checkId}: ${f.title}`,
        "",
        `- **Resource:** ${f.resource}`,
        `- **Details:** ${f.details}`,
        `- **Remediation:** \`${f.remediation}\``,
        ""
      );
    }
  }

  // Other findings (compact)
  const others = filtered.filter(f => f.status === "FAIL" && f.severity !== "CRITICAL" && f.severity !== "HIGH");
  if (others.length > 0) {
    lines.push("## Other Findings", "", "| Check | Severity | Resource | Details |", "|-------|----------|----------|---------|");
    for (const f of others) {
      lines.push(`| ${f.checkId} | ${f.severity} | ${f.resource} | ${f.details.substring(0, 80)} |`);
    }
    lines.push("");
  }

  return lines.filter(l => l !== undefined).join("\n");
}
