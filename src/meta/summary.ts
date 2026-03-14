import type { CheckResult, CheckCategory, Severity } from "../types/index.js";

export interface AuditSummary {
  totalFindings: number;
  byStatus: { pass: number; fail: number; error: number };
  byCategory: Record<string, { pass: number; fail: number; error: number }>;
  bySeverity: Record<string, number>;
  criticalFindings: CheckResult[];
  topRemediation: { action: string; count: number }[];
}

export function auditSummary(findings: CheckResult[]): AuditSummary {
  const byStatus = { pass: 0, fail: 0, error: 0 };
  const byCategory: Record<string, { pass: number; fail: number; error: number }> = {};
  const bySeverity: Record<string, number> = {};
  const remediationMap = new Map<string, number>();

  for (const f of findings) {
    if (f.status === "PASS") byStatus.pass++;
    else if (f.status === "FAIL") byStatus.fail++;
    else if (f.status === "ERROR") byStatus.error++;

    if (!byCategory[f.category]) byCategory[f.category] = { pass: 0, fail: 0, error: 0 };
    if (f.status === "PASS") byCategory[f.category].pass++;
    else if (f.status === "FAIL") byCategory[f.category].fail++;
    else if (f.status === "ERROR") byCategory[f.category].error++;

    if (f.status === "FAIL") {
      bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
    }

    if (f.status === "FAIL" && f.remediation) {
      const key = f.remediation.split("\n")[0].trim();
      remediationMap.set(key, (remediationMap.get(key) || 0) + 1);
    }
  }

  const criticalFindings = findings.filter(
    f => f.status === "FAIL" && (f.severity === "CRITICAL" || f.severity === "HIGH")
  );

  const topRemediation = Array.from(remediationMap.entries())
    .map(([action, count]) => ({ action, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 10);

  return {
    totalFindings: findings.length,
    byStatus,
    byCategory,
    bySeverity,
    criticalFindings,
    topRemediation,
  };
}
