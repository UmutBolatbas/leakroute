import path from 'node:path';
import { fingerprint } from '../../core/fingerprint.js';
import { redact } from '../../core/redact.js';
import type { Finding, Severity } from '../../core/types.js';
import { findEntropyCandidates, shannonEntropy } from './entropy.js';
import { matchSensitiveFile } from './files.js';
import { SECRET_PATTERNS } from './patterns.js';
import { isPlaceholder, isTestLikePath } from './placeholder.js';

export interface TextScanInput {
  /** Repo-relative POSIX path. */
  file: string;
  text: string;
  /**
   * Real line number for each line of `text`. Used by the git history scanner,
   * which only feeds in added lines. Defaults to 1, 2, 3...
   */
  lineNumbers?: readonly number[];
  /** Commit the text came from (git history scans only). */
  commit?: string;
}

interface RawMatch {
  ruleId: string;
  title: string;
  severity: Severity;
  start: number;
  end: number;
  redacted: string;
  reason: string;
  remediation: string;
}

/** Runs the provider patterns and the entropy heuristic over one file's text. */
export function scanTextForSecrets(input: TextScanInput): Finding[] {
  const { file, text } = input;
  const matches: RawMatch[] = [];
  const overlaps = (start: number, end: number) =>
    matches.some((m) => start < m.end && end > m.start);

  for (const pattern of SECRET_PATTERNS) {
    for (const match of text.matchAll(pattern.regex)) {
      const secret = match.groups?.secret;
      const span = match.indices?.groups?.secret;
      if (secret === undefined || span === undefined) continue;
      if (overlaps(span[0], span[1]) || isPlaceholder(secret, file)) continue;

      let severity = pattern.severity;
      const verdict = pattern.check?.(secret, match.groups ?? {}) ?? true;
      if (verdict === false) continue;
      if (typeof verdict === 'string') severity = verdict;

      const redacted = redact(secret);
      matches.push({
        ruleId: pattern.id,
        title: `Possible ${pattern.title}`,
        severity,
        start: span[0],
        end: span[1],
        redacted,
        reason: `Matches the documented ${pattern.title} format (${redacted}). If it is a real credential, anyone who can read this repository can use it.`,
        remediation: pattern.remediation,
      });
    }
  }

  // Generic detection is too noisy in tests and examples, which are full of dummy tokens.
  if (!isTestLikePath(file)) {
    for (const candidate of findEntropyCandidates(file, text)) {
      const end = candidate.index + candidate.value.length;
      if (overlaps(candidate.index, end) || isPlaceholder(candidate.value, file)) continue;

      const redacted = redact(candidate.value);
      const isPassword = candidate.ruleId === 'secret/hardcoded-password';
      matches.push({
        ruleId: candidate.ruleId,
        title: isPassword ? 'Possible hardcoded password' : 'Possible hardcoded secret',
        severity: candidate.severity,
        start: candidate.index,
        end,
        redacted,
        reason: isPassword
          ? `A string literal (${redacted}) is assigned to \`${candidate.name}\`, which looks like a password.`
          : `A high-entropy string (${redacted}, ${shannonEntropy(candidate.value).toFixed(1)} bits/char) is assigned to \`${candidate.name}\`, which looks like a credential name.`,
        remediation:
          'If this is a real credential, rotate it and read it from an environment variable or a secret manager. If it is not, add `leakroute-ignore: <reason>` on this line.',
      });
    }
  }

  const lineStarts = computeLineStarts(text);
  const occurrences = new Map<string, number>();

  return matches
    .sort((a, b) => a.start - b.start)
    .map((m) => {
      const { line, column } = locate(lineStarts, m.start);
      const realLine = input.lineNumbers?.[line - 1] ?? line;

      // Never derived from the secret itself: see fingerprint.ts.
      const key = `${m.ruleId}\u0000${m.redacted}`;
      const nth = (occurrences.get(key) ?? 0) + 1;
      occurrences.set(key, nth);

      const finding: Finding = {
        ruleId: m.ruleId,
        category: 'secret',
        severity: m.severity,
        file,
        line: realLine,
        column,
        title: m.title,
        reason: m.reason,
        remediation: m.remediation,
        fingerprint: input.commit
          ? fingerprint(m.ruleId, file, m.redacted, 'history')
          : fingerprint(m.ruleId, file, m.redacted, nth),
        redactedValue: m.redacted,
      };
      if (input.commit) {
        finding.commit = input.commit;
        finding.reason += ` Found in git history (commit ${input.commit.slice(0, 7)}): it may be gone from the current code but anyone can still recover it from history.`;
      }
      return finding;
    });
}

/**
 * Flags files that should never be committed (`.env`, private keys, credential stores).
 * `content` is `null` for binary or oversized files.
 */
export function scanSensitiveFile(file: string, content: string | null): Finding | null {
  const rule = matchSensitiveFile(path.posix.basename(file));
  if (!rule || (rule.check && !rule.check(content))) return null;
  return {
    ruleId: rule.id,
    category: 'secret',
    severity: rule.severity,
    file,
    line: 1,
    column: 1,
    title: `Possible ${rule.title.charAt(0).toLowerCase()}${rule.title.slice(1)}`,
    reason: `\`${path.posix.basename(file)}\` is a file type that normally holds credentials and should not be in version control.`,
    remediation: rule.remediation,
    fingerprint: fingerprint(rule.id, file),
  };
}

function computeLineStarts(text: string): number[] {
  const starts = [0];
  for (let i = 0; i < text.length; i++) if (text.charCodeAt(i) === 10) starts.push(i + 1);
  return starts;
}

function locate(lineStarts: readonly number[], offset: number): { line: number; column: number } {
  let lo = 0;
  let hi = lineStarts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if ((lineStarts[mid] ?? 0) <= offset) lo = mid;
    else hi = mid - 1;
  }
  return { line: lo + 1, column: offset - (lineStarts[lo] ?? 0) + 1 };
}
