import { countBySeverity } from '../core/severity.js';
import type { Finding, Severity } from '../core/types.js';

export const SEVERITY_BADGE: Record<Severity, string> = {
  high: '🔴 high',
  medium: '🟠 medium',
  low: '🔵 low',
};

/** Zero-width space: breaks @mentions and autolinks without changing what readers see. */
const ZWSP = '​';

/**
 * Makes rendered Markdown safe inside a table cell. GFM splits cells on every
 * `|`, even inside code spans, unless it is escaped.
 */
export function cell(markdown: string): string {
  return markdown.replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
}

/** Wraps text in a code span whose fence no backtick inside it can close. */
export function code(text: string): string {
  const flat = text.replace(/\r?\n/g, ' ');
  const longestRun = Math.max(0, ...(flat.match(/`+/g) ?? []).map((run) => run.length));
  const fence = '`'.repeat(longestRun + 1);
  return longestRun > 0 ? `${fence} ${flat} ${fence}` : `${fence}${flat}${fence}`;
}

/**
 * Escapes plain text so Markdown and HTML in it render literally. Findings quote
 * route paths and names from the scanned code, which a pull request controls, so
 * this also stops them from pinging people (`@team`) or posting links as the bot.
 */
export function escapeText(text: string): string {
  return text
    .replace(/\r?\n/g, ' ')
    .replace(/@/g, `@${ZWSP}`)
    .replace(/:\/\//g, `:/${ZWSP}/`)
    .replace(/www\./gi, (m) => `${m.slice(0, 3)}${ZWSP}.`)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/[\\`*_[\]()#!~]/g, '\\$&');
}

/**
 * Renders a finding message (plain text with `code` spans) as safe Markdown:
 * code spans stay code, everything else is escaped. A stray backtick in a quoted
 * value can shift where spans start, but every segment is still made safe.
 */
export function inline(message: string): string {
  return message
    .split('`')
    .map((part, i) => (i % 2 === 1 ? (part ? code(part) : '') : escapeText(part)))
    .join('');
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
