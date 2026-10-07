import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { z } from 'zod';
import { ConfigError } from './config.js';
import type { Finding } from './types.js';
import { TOOL_NAME } from '../version.js';

/**
 * A baseline records the findings that already exist, so later scans report only
 * new ones. It lets an existing project adopt leakroute without fixing everything
 * first.
 *
 * Entries are matched by fingerprint, which does not depend on line numbers and
 * never contains a secret (see fingerprint.ts). The file has no timestamp, so
 * regenerating an unchanged baseline produces no diff.
 */

const entrySchema = z.object({
  fingerprint: z.string().min(1),
  ruleId: z.string(),
  file: z.string(),
  title: z.string(),
});

const baselineSchema = z.object({
  tool: z.literal(TOOL_NAME),
  version: z.literal(1),
  findings: z.array(entrySchema),
});

export type BaselineEntry = z.infer<typeof entrySchema>;

export function readBaseline(file: string): Set<string> | null {
  if (!existsSync(file)) return null;
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(file, 'utf8'));
  } catch (err) {
    // JSON.parse errors quote the start of the file. The path can come from a
    // config file a pull request controls, so never echo another file's contents.
    const why = err instanceof SyntaxError ? 'not valid JSON' : (err as Error).message;
    throw new ConfigError(`Could not read baseline ${file}: ${why}`);
  }
  const parsed = baselineSchema.safeParse(raw);
  if (!parsed.success) {
    throw new ConfigError(
      `Invalid baseline ${file}. Regenerate it with \`leakroute baseline\`. (${parsed.error.issues[0]?.message ?? 'unknown error'})`,
    );
  }
  return new Set(parsed.data.findings.map((f) => f.fingerprint));
}

export function writeBaseline(file: string, findings: readonly Finding[]): number {
  const entries: BaselineEntry[] = findings
    .map((f) => ({ fingerprint: f.fingerprint, ruleId: f.ruleId, file: f.file, title: f.title }))
    .sort(
      (a, b) =>
        a.file.localeCompare(b.file) ||
        a.ruleId.localeCompare(b.ruleId) ||
        a.fingerprint.localeCompare(b.fingerprint),
    );
  const unique = entries.filter((e, i) => i === 0 || e.fingerprint !== entries[i - 1]?.fingerprint);
  const body = { tool: TOOL_NAME, version: 1 as const, findings: unique };
  writeFileSync(file, `${JSON.stringify(body, null, 2)}\n`);
  return unique.length;
}
