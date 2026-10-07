import path from 'node:path';
import picomatch from 'picomatch';
import { scanGitHistory } from '../git/history.js';
import { analyzeEndpoints, wantsForEndpoints } from '../rules/endpoints/index.js';
import { scanSensitiveFile, scanTextForSecrets } from '../rules/secrets/index.js';
import { readBaseline } from './baseline.js';
import type { ResolvedConfig } from './config.js';
import { createPathFilter, listFiles, readSourceFile } from './files.js';
import { compareFindings } from './severity.js';
import { applySuppressions } from './suppress.js';
import type { Finding, ScanResult, SourceFile } from './types.js';

export interface ScanOptions {
  /** Directory to scan. */
  root: string;
  config: ResolvedConfig;
  /** Set to false to report baselined findings too (used to write a new baseline). */
  useBaseline?: boolean;
}

const READ_CONCURRENCY = 32;

export async function scan(options: ScanOptions): Promise<ScanResult> {
  const started = performance.now();
  const root = path.resolve(options.root);
  const { config } = options;

  const files = await listFiles(root, { ignorePaths: config.ignorePaths });
  const findings: Finding[] = [];
  const endpointSources: SourceFile[] = [];

  await forEachConcurrent(files, READ_CONCURRENCY, async (rel) => {
    const source = await readSourceFile(root, rel, config.maxFileSize);
    if (source && config.scan.endpoints && wantsForEndpoints(rel)) endpointSources.push(source);
    if (config.scan.secrets) {
      const sensitive = scanSensitiveFile(rel, source?.content ?? null);
      if (sensitive) findings.push(sensitive);
      if (source) findings.push(...scanTextForSecrets({ file: rel, text: source.content }));
    }
  });

  let unparsed: string[] = [];
  if (config.scan.endpoints) {
    // Sorted so cross-file resolution is deterministic regardless of read order.
    endpointSources.sort((a, b) => a.path.localeCompare(b.path));
    const endpoints = await analyzeEndpoints(endpointSources, config);
    findings.push(...endpoints.findings);
    unparsed = endpoints.unparsed;
  }

  if (config.scan.secrets && config.gitHistory) {
    const current = new Set(findings.map(secretIdentity));
    const history = await scanGitHistory(root, {
      shouldScan: createPathFilter(config.ignorePaths),
    });
    // A secret that is still in the working tree is already reported there.
    findings.push(...history.filter((f) => !current.has(secretIdentity(f))));
  }

  // Filters, in order: disabled rules, `leakroute-ignore` comments, baseline.
  const isDisabled = config.disableRules.length > 0 ? picomatch(config.disableRules) : () => false;
  const enabled = findings.filter((f) => !isDisabled(f.ruleId));
  const { kept, suppressed } = applySuppressions(root, enabled);

  let reported = kept;
  let baselined = 0;
  if (config.baseline && options.useBaseline !== false) {
    const known = readBaseline(path.resolve(root, config.baseline));
    if (known) {
      reported = kept.filter((f) => !known.has(f.fingerprint));
      baselined = kept.length - reported.length;
    }
  }

  return {
    findings: reported.sort(compareFindings),
    filesScanned: files.length,
    unparsedFiles: unparsed,
    suppressed: suppressed.length,
    baselined,
    durationMs: Math.round(performance.now() - started),
  };
}

function secretIdentity(f: Finding): string {
  return `${f.ruleId}\u0000${f.file}\u0000${f.redactedValue ?? ''}`;
}

async function forEachConcurrent<T>(
  items: readonly T[],
  limit: number,
  fn: (item: T) => Promise<void>,
): Promise<void> {
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const item = items[next++] as T;
      await fn(item);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
}
