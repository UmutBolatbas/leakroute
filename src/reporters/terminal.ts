import pc from 'picocolors';
import { countBySeverity } from '../core/severity.js';
import type { Finding, ScanResult, Severity } from '../core/types.js';
import { TOOL_NAME, VERSION } from '../version.js';

export interface TerminalOptions {
  color: boolean;
}

export function renderTerminal(result: ScanResult, options: TerminalOptions): string {
  const c = pc.createColors(options.color);
  const badge: Record<Severity, (s: string) => string> = {
    high: (s) => c.bold(c.red(s)),
    medium: (s) => c.yellow(s),
    low: (s) => c.blue(s),
  };

  const out: string[] = [
    c.dim(
      `${TOOL_NAME} v${VERSION} · scanned ${result.filesScanned} files in ${result.durationMs}ms`,
    ),
    '',
  ];

  const byFile = new Map<string, Finding[]>();
  for (const f of result.findings) byFile.set(f.file, [...(byFile.get(f.file) ?? []), f]);

  for (const [file, findings] of byFile) {
    out.push(c.underline(file));
    for (const f of findings) {
      const location = `${f.line}:${f.column}`.padEnd(8);
      const severity = badge[f.severity](f.severity.toUpperCase().padEnd(6));
      out.push(`  ${c.dim(location)}${severity}  ${f.title}  ${c.dim(f.ruleId)}`);
      if (f.commit) out.push(`  ${' '.repeat(8)}${c.dim('commit:')} ${f.commit.slice(0, 12)}`);
      out.push(`  ${' '.repeat(8)}${c.dim('why:')} ${f.reason}`);
      out.push(`  ${' '.repeat(8)}${c.dim('fix:')} ${f.remediation}`);
    }
    out.push('');
  }

  if (result.findings.length === 0) {
    out.push(c.green('✔ No issues found.'));
  } else {
    const counts = countBySeverity(result.findings);
    const noun = result.findings.length === 1 ? 'possible issue' : 'possible issues';
    out.push(
      c.bold(`✖ ${result.findings.length} ${noun}`) +
        ` (${badge.high(`${counts.high} high`)}, ${badge.medium(`${counts.medium} medium`)}, ${badge.low(`${counts.low} low`)})`,
    );
    out.push(c.dim('Static analysis can be wrong: each finding explains why it was flagged.'));
  }
  return out.join('\n');
}
