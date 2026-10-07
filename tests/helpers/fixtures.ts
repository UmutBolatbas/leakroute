import {
  cpSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { defaultConfig, type ResolvedConfig } from '../../src/core/config.js';
import { scan } from '../../src/core/scanner.js';
import type { Finding } from '../../src/core/types.js';
import { createFakeSecrets, type FakeSecrets } from './fake-secrets.js';

export const FIXTURES = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'fixtures');

export interface Materialized {
  dir: string;
  secrets: FakeSecrets;
  cleanup: () => void;
}

/**
 * Copies a fixture directory to a temp dir (outside any git repo) and replaces
 * `__NAME__` placeholders with generated fake secrets. `renames` turns stored
 * names into real ones (`env.tmpl` -> `.env`) so the repo never holds a real `.env`.
 */
export function materialize(
  fixtureDir: string,
  renames: Record<string, string> = {},
): Materialized {
  const dir = mkdtempSync(path.join(tmpdir(), 'leakroute-'));
  cpSync(path.join(FIXTURES, fixtureDir), dir, { recursive: true });
  const secrets = createFakeSecrets();

  for (const file of walk(dir)) {
    let content = readFileSync(file, 'utf8');
    for (const [token, value] of Object.entries(secrets))
      content = content.split(token).join(value);
    writeFileSync(file, content);
  }
  for (const [from, to] of Object.entries(renames)) {
    cpSync(path.join(dir, from), path.join(dir, to));
    rmSync(path.join(dir, from));
  }
  return { dir, secrets, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

function walk(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const full = path.join(dir, name);
    return statSync(full).isDirectory() ? walk(full) : [full];
  });
}

export async function scanDir(
  dir: string,
  overrides: Partial<ResolvedConfig> = {},
): Promise<Finding[]> {
  const config = { ...defaultConfig(), ...overrides };
  return (await scan({ root: dir, config })).findings;
}

/**
 * Reads `expect: <rule-id>` markers from a fixture file.
 * Returns one `rule-id@line` entry per marker.
 */
export function expectedMarkers(dir: string, rel: string): string[] {
  return readFileSync(path.join(dir, rel), 'utf8')
    .split(/\r?\n/)
    .flatMap((line, i) => [...line.matchAll(/expect: ([\w/-]+)/g)].map((m) => `${m[1]}@${i + 1}`));
}
