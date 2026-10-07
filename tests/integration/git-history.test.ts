import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, unlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createFakeSecrets } from '../helpers/fake-secrets.js';
import { scanDir } from '../helpers/fixtures.js';

describe('--git-history', () => {
  const secrets = createFakeSecrets(7);
  let dir: string;
  const git = (...args: string[]) =>
    execFileSync(
      'git',
      [
        '-c',
        'user.name=t',
        '-c',
        'user.email=t@example.com',
        '-c',
        'commit.gpgsign=false',
        ...args,
      ],
      {
        cwd: dir,
        stdio: 'pipe',
      },
    );

  beforeAll(() => {
    dir = mkdtempSync(path.join(tmpdir(), 'leakroute-git-'));
    git('init', '-q', '-b', 'main');
    writeFileSync(
      path.join(dir, 'app.ts'),
      `export const port = 3000;\nexport const key = '${secrets.__STRIPE__}';\n`,
    );
    writeFileSync(path.join(dir, '.env'), `GITHUB_TOKEN=${secrets.__GITHUB_PAT__}\n`);
    git('add', '.');
    git('commit', '-q', '-m', 'add config');
    // "Fix" the leak in a later commit: the secret is gone from HEAD but not from history.
    writeFileSync(
      path.join(dir, 'app.ts'),
      `export const port = 3000;\nexport const key = process.env.KEY;\n`,
    );
    unlinkSync(path.join(dir, '.env'));
    git('commit', '-q', '-am', 'remove secrets');
  });
  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  it('finds nothing in the working tree', async () => {
    expect(await scanDir(dir)).toEqual([]);
  });

  it('finds removed secrets in history with commit and line', async () => {
    const findings = await scanDir(dir, { gitHistory: true });
    const summary = findings.map((f) => `${f.ruleId}@${f.file}:${f.line}`).sort();
    expect(summary).toEqual([
      'secret/env-file@.env:1',
      'secret/github-token@.env:1',
      'secret/stripe-live-key@app.ts:2',
    ]);
    for (const f of findings) {
      expect(f.commit).toMatch(/^[0-9a-f]{40}$/);
      expect(JSON.stringify(f)).not.toContain(secrets.__STRIPE__);
      expect(JSON.stringify(f)).not.toContain(secrets.__GITHUB_PAT__);
    }
  });
});
