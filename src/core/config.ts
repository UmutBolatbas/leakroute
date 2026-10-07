import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { parse as parseYaml } from 'yaml';
import { z } from 'zod';
import type { FailOn } from './types.js';

export const CONFIG_FILE_NAMES = ['.leakroute.yml', '.leakroute.yaml'] as const;
export const DEFAULT_BASELINE = '.leakroute-baseline.json';

const fileSchema = z
  .object({
    'fail-on': z.enum(['high', 'medium', 'low', 'none']).default('high'),
    scan: z
      .object({
        endpoints: z.boolean().default(true),
        secrets: z.boolean().default(true),
      })
      .strict()
      .prefault({}),
    'auth-middleware': z.array(z.string().min(1)).default([]),
    'public-routes': z.array(z.string().min(1)).default([]),
    'ignore-paths': z.array(z.string().min(1)).default([]),
    'max-file-size': z.number().int().positive().default(1_000_000),
    'git-history': z.boolean().default(false),
    'disable-rules': z.array(z.string().min(1)).default([]),
    baseline: z.union([z.string().min(1), z.literal(false)]).default(DEFAULT_BASELINE),
  })
  .strict();

export interface ResolvedConfig {
  failOn: FailOn;
  scan: { endpoints: boolean; secrets: boolean };
  /** Extra auth middleware/decorator names, added to the built-in defaults. */
  authMiddleware: string[];
  /** Extra public route patterns, added to the built-in defaults. */
  publicRoutes: string[];
  /** Glob patterns (relative to the scan root) to skip. */
  ignorePaths: string[];
  /** Files larger than this many bytes are skipped. */
  maxFileSize: number;
  gitHistory: boolean;
  /** Rule ids or globs (`secret/jwt`, `endpoint/*`) that are not reported. */
  disableRules: string[];
  /** Baseline file relative to the scan root, or `null` to not use one. */
  baseline: string | null;
}

export class ConfigError extends Error {
  override name = 'ConfigError';
}

export function defaultConfig(): ResolvedConfig {
  return fromParsed(fileSchema.parse({}));
}

export interface LoadedConfig {
  config: ResolvedConfig;
  /** Absolute path of the file that was loaded, if any. */
  source?: string;
}

/** Loads `.leakroute.yml` from `root`, or from `explicitPath` when given. */
export function loadConfig(root: string, explicitPath?: string): LoadedConfig {
  const candidates = explicitPath
    ? [path.resolve(root, explicitPath)]
    : CONFIG_FILE_NAMES.map((name) => path.join(root, name));
  const source = candidates.find((p) => existsSync(p));

  if (!source) {
    if (explicitPath) throw new ConfigError(`Config file not found: ${explicitPath}`);
    return { config: defaultConfig() };
  }

  let raw: unknown;
  try {
    raw = parseYaml(readFileSync(source, 'utf8')) ?? {};
  } catch (err) {
    throw new ConfigError(`Could not parse ${path.basename(source)}: ${(err as Error).message}`);
  }

  const parsed = fileSchema.safeParse(raw);
  if (!parsed.success) {
    const details = parsed.error.issues
      .map((issue) => `  - ${issue.path.join('.') || '(root)'}: ${issue.message}`)
      .join('\n');
    throw new ConfigError(`Invalid ${path.basename(source)}:\n${details}`);
  }
  return { config: fromParsed(parsed.data), source };
}

function fromParsed(data: z.output<typeof fileSchema>): ResolvedConfig {
  return {
    failOn: data['fail-on'],
    scan: { ...data.scan },
    authMiddleware: data['auth-middleware'],
    publicRoutes: data['public-routes'],
    ignorePaths: data['ignore-paths'],
    maxFileSize: data['max-file-size'],
    gitHistory: data['git-history'],
    disableRules: data['disable-rules'],
    baseline: data.baseline === false ? null : data.baseline,
  };
}
