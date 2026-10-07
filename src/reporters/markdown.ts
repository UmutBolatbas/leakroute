import { countBySeverity } from '../core/severity.js';
import type { Finding, Severity } from '../core/types.js';

export const SEVERITY_BADGE: Record<Severity, string> = {
  high: '🔴 high',
  medium: '🟠 medium',
  low: '🔵 low',
};

/** Makes text safe inside a Markdown table cell. */
export function cell(text: string): string {
  return text.replace(/\\/g, '\\\\').replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
}

/** Wraps text in a code span that survives backticks inside it. */
export function code(text: string): string {
  const fence = text.includes('`') ? '``' : '`';
  return `${fence}${text.includes('`') ? ` ${text} ` : text}${fence}`;
}

/**
 * Builds a link to the finding in the repository, or a plain code span when no
 * base URL is known (e.g. outside GitHub Actions).
 */
export function location(f: Finding, linkBase?: string): string {
  const label = code(`${f.file}:${f.line}`);
  if (!linkBase || f.commit) return label;
  const encoded = f.file.split('/').map(encodeURIComponent).join('/');
  return `[${label}](${linkBase}${encoded}#L${f.line})`;
}

export function countsLine(findings: readonly Finding[]): string {
  const counts = countBySeverity(findings);
  return `🔴 ${counts.high} high · 🟠 ${counts.medium} medium · 🔵 ${counts.low} low`;
}
