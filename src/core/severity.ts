import type { FailOn, Finding, Severity } from './types.js';

const RANK: Record<Severity, number> = { low: 1, medium: 2, high: 3 };

export const SEVERITIES: readonly Severity[] = ['high', 'medium', 'low'];

export function severityRank(severity: Severity): number {
  return RANK[severity];
}

export function compareFindings(a: Finding, b: Finding): number {
  return (
    severityRank(b.severity) - severityRank(a.severity) ||
    a.file.localeCompare(b.file) ||
    a.line - b.line ||
    a.column - b.column ||
    a.ruleId.localeCompare(b.ruleId)
  );
}

/** True when at least one finding is at or above the `fail-on` threshold. */
export function exceedsThreshold(findings: readonly Finding[], failOn: FailOn): boolean {
  if (failOn === 'none') return false;
  const min = RANK[failOn];
  return findings.some((f) => RANK[f.severity] >= min);
}

export function countBySeverity(findings: readonly Finding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = { high: 0, medium: 0, low: 0 };
  for (const f of findings) counts[f.severity]++;
  return counts;
}
