import { readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import picomatch from 'picomatch';
import type { Finding } from './types.js';

/**
 * Line-level suppressions:
 *
 *   const key = 'pk_test_123'; // leakroute-ignore: publishable test key
 *   # leakroute-ignore[endpoint/flask-unprotected-route]: public status page
 *   @app.get("/status")
 *
 * A marker silences findings on its own line, or on the next line when the
 * marker line holds nothing but the comment. A reason is required: a bare
 * `leakroute-ignore` does not silence anything, so every exception is explained.
 */

const MARKER = /leakroute-ignore(?:\[([^\]]*)\])?\s*:\s*(.*)$/;
/** Comment closers to strip from the end of a reason. */
const CLOSER = /\s*(?:\*\/|-->|#\}|%\}|\}\})\s*$/;
/** A line that contains only a comment (in any common syntax) up to the marker. */
const COMMENT_ONLY = /^\s*(?:\/\/|#|\/\*+|\*|<!--|--|;|\{#|\{\{!?--)\s*leakroute-ignore/;

const MAX_BYTES = 5_000_000;

export interface Suppression {
  /** 1-based line the suppression applies to. */
  line: number;
  /** Rule globs, or `null` for every rule. */
  rules: string[] | null;
  reason: string;
}

export function parseSuppressions(content: string): Suppression[] {
  const out: Suppression[] = [];
  const lines = content.split(/\r?\n/);
  lines.forEach((text, index) => {
    const match = MARKER.exec(text);
    if (!match) return;
    const reason = (match[2] ?? '').replace(CLOSER, '').trim();
    if (!reason) return;
    const rules = match[1]
      ?.split(',')
      .map((r) => r.trim())
      .filter(Boolean);
    const line = COMMENT_ONLY.test(text) ? index + 2 : index + 1;
    out.push({ line, rules: rules && rules.length > 0 ? rules : null, reason });
  });
  return out;
}

/** Splits findings into kept and suppressed, reading each affected file once. */
export function applySuppressions(
  root: string,
  findings: readonly Finding[],
): { kept: Finding[]; suppressed: Finding[] } {
  const cache = new Map<string, Suppression[]>();
  const suppressionsFor = (file: string) => {
    let entries = cache.get(file);
    if (!entries) {
      entries = readSuppressions(path.join(root, file));
      cache.set(file, entries);
    }
    return entries;
  };

  const kept: Finding[] = [];
  const suppressed: Finding[] = [];
  for (const f of findings) {
    // History findings point at lines that may no longer exist; use the baseline for those.
    const silenced =
      !f.commit &&
      suppressionsFor(f.file).some(
        (s) => s.line === f.line && (s.rules === null || picomatch.isMatch(f.ruleId, s.rules)),
      );
    (silenced ? suppressed : kept).push(f);
  }
  return { kept, suppressed };
}

function readSuppressions(absPath: string): Suppression[] {
  try {
    if (statSync(absPath).size > MAX_BYTES) return [];
    const content = readFileSync(absPath, 'utf8');
    return content.includes('leakroute-ignore') ? parseSuppressions(content) : [];
  } catch {
    return [];
  }
}
