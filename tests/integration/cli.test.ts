import { writeFileSync } from 'node:fs';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, run } from '../../src/cli/program.js';
import { materialize, type Materialized } from '../helpers/fixtures.js';

async function cli(...argv: string[]) {
  let stdout = '';
  let stderr = '';
  const code = await run(argv, {
    stdout: (t) => (stdout += t),
    stderr: (t) => (stderr += t),
    color: false,
  });
  return { code, stdout, stderr };
}

describe('cli', () => {
  let vulnerable: Materialized;
  let safe: Materialized;

  beforeAll(() => {
    vulnerable = materialize('vulnerable/secrets', { 'env.tmpl': '.env' });
    safe = materialize('safe/secrets');
  });
  afterAll(() => {
    vulnerable.cleanup();
    safe.cleanup();
  });

  it('exits 1 when findings reach the default threshold (high)', async () => {
    const { code, stdout } = await cli('scan', vulnerable.dir);
    expect(code).toBe(EXIT_FINDINGS);
    expect(stdout).toContain('secret/openai-api-key');
    expect(stdout).toMatch(/\d+ possible issues/);
  });

  it('exits 0 on a clean directory', async () => {
    const { code, stdout } = await cli('scan', safe.dir);
    expect(code).toBe(EXIT_OK);
    expect(stdout).toContain('No issues found');
  });

  it('respects --fail-on none', async () => {
    expect((await cli('scan', vulnerable.dir, '--fail-on', 'none')).code).toBe(EXIT_OK);
  });

  it('prints parseable JSON', async () => {
    const { stdout } = await cli('scan', vulnerable.dir, '--format', 'json');
    const report = JSON.parse(stdout) as {
      summary: { total: number; high: number };
      findings: unknown[];
    };
    expect(report.summary.total).toBe(report.findings.length);
    expect(report.summary.high).toBeGreaterThan(0);
  });

  it('--no-secrets disables secret detection', async () => {
    const { code, stdout } = await cli('scan', vulnerable.dir, '--no-secrets');
    expect(code).toBe(EXIT_OK);
    expect(stdout).toContain('No issues found');
  });

  it('reads fail-on and ignore-paths from .leakroute.yml', async () => {
    writeFileSync(
      path.join(vulnerable.dir, '.leakroute.yml'),
      'fail-on: none\nignore-paths:\n  - "**/*.py"\n',
    );
    const { code, stdout } = await cli('scan', vulnerable.dir);
    expect(code).toBe(EXIT_OK);
    expect(stdout).not.toContain('aws_settings.py');
  });

  it('exits 2 with a readable message on an invalid config', async () => {
    writeFileSync(path.join(safe.dir, '.leakroute.yml'), 'fail-on: sometimes\n');
    const { code, stderr } = await cli('scan', safe.dir);
    expect(code).toBe(EXIT_ERROR);
    expect(stderr).toContain('fail-on');
  });

  it('rejects unknown formats', async () => {
    expect((await cli('scan', safe.dir, '--format', 'xml')).code).toBe(EXIT_ERROR);
  });
});
